(* main.ml — Entry point for the taint analysis tool *)

open Parser
open Taint

let () =
  if Array.length Sys.argv < 2 then begin
    Printf.eprintf "Usage: %s <source-file>\n" Sys.argv.(0);
    exit 1
  end;

  let filename = Sys.argv.(1) in
  let ic = open_in filename in
  let n = in_channel_length ic in
  let source = Bytes.create n in
  really_input ic source 0 n;
  close_in ic;

  let input = Bytes.to_string source in
  Printf.printf "=== Static Taint Analysis ===\n";
  Printf.printf "Analyzing: %s\n\n" filename;

  let program = parse input in
  let warnings = analyze program in
  print_results warnings
