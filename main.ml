(* main.ml — Entry point for the taint analysis tool *)

open Parser
open Taint

(* ===== CLI argument parsing ===== *)

type cli_args = {
  source_file : string;
  policy_file : string option;
}

let usage () =
  Printf.eprintf "Usage: %s [--policy <policy.json>] <source-file.imp>\n" Sys.argv.(0);
  Printf.eprintf "       %s [--policy <policy.json>] --python <source-file.py>\n" Sys.argv.(0);
  exit 1

let parse_args () =
  let n = Array.length Sys.argv in
  if n < 2 then usage ();
  let policy_file = ref None in
  let source_file = ref "" in
  let i = ref 1 in
  while !i < n do
    (match Sys.argv.(!i) with
    | "--policy" ->
      if !i + 1 >= n then (Printf.eprintf "Error: --policy requires a filename\n"; exit 1);
      policy_file := Some Sys.argv.(!i + 1);
      i := !i + 2
    | arg ->
      source_file := arg;
      incr i)
  done;
  if !source_file = "" then usage ();
  { source_file = !source_file; policy_file = !policy_file }

(* ===== Main ===== *)

let () =
  let args = parse_args () in

  (* Load policy: from file if given, else use default *)
  let policy = match args.policy_file with
    | Some path ->
      Printf.printf "Loading policy: %s\n" path;
      load_policy path
    | None ->
      default_policy
  in

  let filename = args.source_file in
  let ic = open_in filename in
  let n = in_channel_length ic in
  let source = Bytes.create n in
  really_input ic source 0 n;
  close_in ic;
  let input = Bytes.to_string source in

  Printf.printf "=== Static Taint Analysis ===\n";
  Printf.printf "Analyzing: %s\n" filename;
  Printf.printf "Sources:    [%s]\n" (String.concat ", " policy.sources);
  Printf.printf "Sinks:      [%s]\n" (String.concat ", " policy.sinks);
  Printf.printf "Sanitizers: [%s]\n\n" (String.concat ", " policy.sanitizers);

  let program = parse input in
  let warnings = analyze ~policy program in
  print_results warnings
