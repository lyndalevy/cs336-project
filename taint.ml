(* taint.ml — Static taint analysis engine *)

open Ast

(* ===== Configuration ===== *)

(* Sources: functions/constructs that introduce tainted data *)
let sources = ["input"]

(* Sinks: dangerous operations that should not receive tainted data *)
let sinks = ["sql_exec"; "sql_query"; "html_output"; "eval"; "exec";
             "system"; "redirect"; "send_response"; "print"]

(* Sanitizers: functions that clean tainted data *)
let sanitizers = ["escape"; "validate"; "sanitize"; "encode";
                  "html_escape"; "parameterize"; "clean"]

(* ===== Taint State ===== *)

module StringSet = Set.Make(String)
module StringMap = Map.Make(String)

(* Each tainted variable tracks where it was originally tainted *)
type taint_origin = {
  source_var : string;    (* original source variable *)
  source_line : int;      (* line where tainting occurred *)
}

type taint_state = taint_origin StringMap.t

(* ===== Warnings ===== *)

type warning = {
  sink_name : string;
  sink_line : int;
  tainted_var : string;
  origin : taint_origin;
  path : string list;      (* variable flow path *)
}

(* ===== Analysis ===== *)

(* Collect all variables referenced in an expression *)
let rec expr_vars (e : expr) : StringSet.t =
  match e with
  | Num _ -> StringSet.empty
  | Var v -> StringSet.singleton v
  | BinOp (_, e1, e2) -> StringSet.union (expr_vars e1) (expr_vars e2)

(* Check if any variable in an expression is tainted *)
let expr_is_tainted (state : taint_state) (e : expr) : taint_origin option =
  let vars = expr_vars e in
  StringSet.fold (fun v acc ->
    match acc with
    | Some _ -> acc
    | None -> StringMap.find_opt v state
  ) vars None

(* Build a flow path from origin to current variable *)
let build_path (origin : taint_origin) (current_var : string) : string list =
  if origin.source_var = current_var then [current_var]
  else [origin.source_var; current_var]

(* Merge two taint states (union — sound over-approximation) *)
let merge_states (s1 : taint_state) (s2 : taint_state) : taint_state =
  StringMap.union (fun _k v1 _v2 -> Some v1) s1 s2

(* States are equal if they have the same tainted variables *)
let states_equal (s1 : taint_state) (s2 : taint_state) : bool =
  StringMap.equal (fun a b -> a.source_var = b.source_var) s1 s2

(* ===== Core Analysis with Line Tracking ===== *)

let line_counter = ref 0

let next_line () =
  incr line_counter;
  !line_counter

let reset_lines () =
  line_counter := 0

(* Analyze a single statement, return updated state and any warnings *)
let rec analyze_stmt (state : taint_state) (stmt : stmt) : taint_state * warning list =
  let line = next_line () in
  match stmt with
  | Input v ->
    (* input is a source — variable becomes tainted *)
    let origin = { source_var = v; source_line = line } in
    let state' = StringMap.add v origin state in
    (state', [])

  | Assign (v, e) ->
    (* x := expr — x is tainted if any var in expr is tainted *)
    (match expr_is_tainted state e with
     | Some origin ->
       let origin' = { origin with source_var = origin.source_var } in
       let state' = StringMap.add v origin' state in
       (state', [])
     | None ->
       (* assignment from clean data removes taint *)
       let state' = StringMap.remove v state in
       (state', []))

  | Call (name, args) ->
    if List.mem name sanitizers then begin
      (* sanitizer call — remove taint from all argument variables *)
      let state' = List.fold_left (fun st arg ->
        let vars = expr_vars arg in
        StringSet.fold (fun v s -> StringMap.remove v s) vars st
      ) state args in
      (state', [])
    end
    else if List.mem name sinks then begin
      (* sink call — check if any argument is tainted *)
      let warnings = List.fold_left (fun ws arg ->
        match expr_is_tainted state arg with
        | Some origin ->
          let tainted_var = match arg with
            | Var v -> v
            | _ -> "expr"
          in
          let w = {
            sink_name = name;
            sink_line = line;
            tainted_var;
            origin;
            path = build_path origin tainted_var @ [name];
          } in
          w :: ws
        | None -> ws
      ) [] args in
      (state, warnings)
    end
    else
      (state, [])

  | Print e ->
    (* print is a potential sink *)
    let warnings = match expr_is_tainted state e with
      | Some origin ->
        let tainted_var = match e with Var v -> v | _ -> "expr" in
        [{ sink_name = "print";
           sink_line = line;
           tainted_var;
           origin;
           path = build_path origin tainted_var @ ["print"] }]
      | None -> []
    in
    (state, warnings)

  | If (_cond, then_body, else_body) ->
    (* analyze both branches, merge results (sound over-approximation) *)
    let then_state, then_warns = analyze_stmts state then_body in
    let else_state, else_warns = analyze_stmts state else_body in
    let merged = merge_states then_state else_state in
    (merged, then_warns @ else_warns)

  | While (_cond, body) ->
    (* iterate to fixed point *)
    let rec fixpoint current_state =
      let new_state, warns = analyze_stmts current_state body in
      let merged = merge_states current_state new_state in
      if states_equal merged current_state then
        (merged, warns)
      else
        fixpoint merged
    in
    fixpoint state

and analyze_stmts (state : taint_state) (stmts : stmt list) : taint_state * warning list =
  List.fold_left (fun (st, ws) s ->
    let st', ws' = analyze_stmt st s in
    (st', ws @ ws')
  ) (state, []) stmts

(* ===== Main Entry Point ===== *)

let analyze (prog : program) : warning list =
  reset_lines ();
  let _final_state, warnings = analyze_stmts StringMap.empty prog in
  warnings

(* ===== Pretty Printing ===== *)

let format_warning (w : warning) : string =
  Printf.sprintf
    "WARNING: Tainted data flows to sink at line %d\n\
    \  Source: input at line %d (variable '%s')\n\
    \  Sink: %s at line %d\n\
    \  Path: %s"
    w.sink_line
    w.origin.source_line
    w.origin.source_var
    w.sink_name
    w.sink_line
    (String.concat " -> " w.path)

let print_results (warnings : warning list) =
  if warnings = [] then
    print_endline "No taint violations found. Program is clean."
  else begin
    Printf.printf "Found %d taint violation(s):\n\n" (List.length warnings);
    List.iter (fun w ->
      print_endline (format_warning w);
      print_endline ""
    ) warnings
  end
