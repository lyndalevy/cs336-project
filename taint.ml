(* taint.ml — Static taint analysis engine *)

open Ast

(* ===== Policy: Sources, Sinks, Sanitizers ===== *)

type policy = {
  sources    : string list;
  sinks      : string list;
  sanitizers : string list;
}

(* Default built-in policy — used when no external policy file is given *)
let default_policy = {
  sources    = ["input"; "get_param"; "post_param"; "read_file"; "env_var"];
  sinks      = ["sql_exec"; "sql_query"; "html_output"; "eval"; "exec";
                "system"; "redirect"; "send_response"; "print"];
  sanitizers = ["escape"; "validate"; "sanitize"; "encode";
                "html_escape"; "parameterize"; "clean"];
}

(* ===== Minimal JSON policy loader ===== *)
(*
  Parses a policy JSON file with the structure:
    {
      "sources":    ["input", "get_param"],
      "sinks":      ["sql_exec", "html_output"],
      "sanitizers": ["escape", "sanitize"]
    }
  Each key is optional - missing keys fall back to the default_policy values.
  Uses only the OCaml standard library (no Yojson dependency).
*)

let parse_json_string_array s =
  let results = ref [] in
  let i = ref 0 in
  let n = String.length s in
  while !i < n do
    if s.[!i] = '"' then begin
      incr i;
      let start = !i in
      while !i < n && s.[!i] <> '"' do incr i done;
      let word = String.sub s start (!i - start) in
      results := word :: !results;
      incr i
    end else incr i
  done;
  List.rev !results

let extract_array json key =
  let pattern = "\"" ^ key ^ "\"" in
  let klen = String.length pattern in
  let jlen = String.length json in
  try
    let found = ref (-1) in
    let i = ref 0 in
    while !i <= jlen - klen && !found = -1 do
      if String.sub json !i klen = pattern then found := !i;
      incr i
    done;
    if !found = -1 then None
    else begin
      let j = ref (!found + klen) in
      while !j < jlen && json.[!j] <> '[' do incr j done;
      if !j >= jlen then None
      else begin
        let start = !j in
        while !j < jlen && json.[!j] <> ']' do incr j done;
        if !j >= jlen then None
        else Some (String.sub json start (!j - start + 1))
      end
    end
  with _ -> None

let load_policy (path : string) : policy =
  try
    let ic = open_in path in
    let n = in_channel_length ic in
    let buf = Bytes.create n in
    really_input ic buf 0 n;
    close_in ic;
    let json = Bytes.to_string buf in
    let get_list key default =
      match extract_array json key with
      | None -> default
      | Some arr_str ->
        let items = parse_json_string_array arr_str in
        if items = [] then default else items
    in
    {
      sources    = get_list "sources"    default_policy.sources;
      sinks      = get_list "sinks"      default_policy.sinks;
      sanitizers = get_list "sanitizers" default_policy.sanitizers;
    }
  with
  | Sys_error msg ->
    Printf.eprintf "Warning: could not load policy '%s': %s\nUsing default policy.\n" path msg;
    default_policy
  | _ ->
    Printf.eprintf "Warning: failed to parse policy '%s'. Using default policy.\n" path;
    default_policy

(* ===== Taint State ===== *)

module StringSet = Set.Make(String)
module StringMap = Map.Make(String)

type taint_origin = {
  source_var  : string;
  source_line : int;
}

type taint_state = taint_origin StringMap.t

(* ===== Warnings ===== *)

type warning = {
  sink_name   : string;
  sink_line   : int;
  tainted_var : string;
  origin      : taint_origin;
  path        : string list;
}

(* ===== Analysis helpers ===== *)

let rec expr_vars (e : expr) : StringSet.t =
  match e with
  | Num _           -> StringSet.empty
  | Var v           -> StringSet.singleton v
  | BinOp (_, a, b) -> StringSet.union (expr_vars a) (expr_vars b)

let expr_is_tainted (state : taint_state) (e : expr) : taint_origin option =
  let vars = expr_vars e in
  StringSet.fold (fun v acc ->
    match acc with
    | Some _ -> acc
    | None   -> StringMap.find_opt v state
  ) vars None

let build_path (origin : taint_origin) (current_var : string) : string list =
  if origin.source_var = current_var then [current_var]
  else [origin.source_var; current_var]

let merge_states (s1 : taint_state) (s2 : taint_state) : taint_state =
  StringMap.union (fun _k v1 _v2 -> Some v1) s1 s2

let states_equal (s1 : taint_state) (s2 : taint_state) : bool =
  StringMap.equal (fun a b -> a.source_var = b.source_var) s1 s2

(* ===== Line counter ===== *)

let line_counter = ref 0
let next_line () = incr line_counter; !line_counter
let reset_lines () = line_counter := 0

(* ===== Core analysis (policy-parametric) ===== *)

let rec analyze_stmt (policy : policy) (state : taint_state) (stmt : stmt)
    : taint_state * warning list =
  let line = next_line () in
  match stmt with

  | Input v ->
    let origin = { source_var = v; source_line = line } in
    (StringMap.add v origin state, [])

  | Assign (v, e) ->
    (match expr_is_tainted state e with
     | Some origin ->
       (StringMap.add v origin state, [])
     | None ->
       (StringMap.remove v state, []))

  | Call (name, args) ->
    if List.mem name policy.sanitizers then begin
      let state' = List.fold_left (fun st arg ->
        let vars = expr_vars arg in
        StringSet.fold (fun v s -> StringMap.remove v s) vars st
      ) state args in
      (state', [])
    end
    else if List.mem name policy.sinks then begin
      let warnings = List.fold_left (fun ws arg ->
        match expr_is_tainted state arg with
        | Some origin ->
          let tainted_var = match arg with Var v -> v | _ -> "expr" in
          { sink_name   = name;
            sink_line   = line;
            tainted_var;
            origin;
            path = build_path origin tainted_var @ [name] } :: ws
        | None -> ws
      ) [] args in
      (state, warnings)
    end
    else if List.mem name policy.sources then begin
      (match args with
       | [Var v] ->
         let origin = { source_var = v; source_line = line } in
         (StringMap.add v origin state, [])
       | _ -> (state, []))
    end
    else
      (state, [])

  | Print e ->
    if List.mem "print" policy.sinks then
      let warnings = match expr_is_tainted state e with
        | Some origin ->
          let tainted_var = match e with Var v -> v | _ -> "expr" in
          [{ sink_name = "print"; sink_line = line; tainted_var; origin;
             path = build_path origin tainted_var @ ["print"] }]
        | None -> []
      in
      (state, warnings)
    else
      (state, [])

  | If (_cond, then_body, else_body) ->
    let then_state, then_warns = analyze_stmts policy state then_body in
    let else_state, else_warns = analyze_stmts policy state else_body in
    (merge_states then_state else_state, then_warns @ else_warns)

  | While (_cond, body) ->
    let rec fixpoint s =
      let s', ws = analyze_stmts policy s body in
      let merged  = merge_states s s' in
      if states_equal merged s then (merged, ws) else fixpoint merged
    in
    fixpoint state

and analyze_stmts (policy : policy) (state : taint_state) (stmts : stmt list)
    : taint_state * warning list =
  List.fold_left (fun (st, ws) s ->
    let st', ws' = analyze_stmt policy st s in
    (st', ws @ ws')
  ) (state, []) stmts

(* ===== Entry point ===== *)

let analyze ?(policy = default_policy) (prog : program) : warning list =
  reset_lines ();
  let _final, warnings = analyze_stmts policy StringMap.empty prog in
  warnings

(* ===== Pretty printing ===== *)

let format_warning (w : warning) : string =
  Printf.sprintf
    "WARNING: Tainted data flows to sink at line %d\n\
    \  Source: input at line %d (variable '%s')\n\
    \  Sink:   %s at line %d\n\
    \  Path:   %s"
    w.sink_line
    w.origin.source_line w.origin.source_var
    w.sink_name w.sink_line
    (String.concat " -> " w.path)

let print_results (warnings : warning list) =
  if warnings = [] then
    print_endline "No taint violations found. Program is clean."
  else begin
    Printf.printf "Found %d taint violation(s):\n\n" (List.length warnings);
    List.iter (fun w -> print_endline (format_warning w); print_endline "") warnings
  end
