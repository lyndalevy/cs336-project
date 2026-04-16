(* ast.ml — AST type definitions for IMP-Core (Variant A) *)

type op =
  | Add | Sub | Mul | Div
  | Eq  | Neq | Lt  | Gt

type expr =
  | Num of int
  | Var of string
  | BinOp of op * expr * expr

type stmt =
  | Assign of string * expr          (* x := expr *)
  | If of expr * stmt list * stmt list  (* if expr then ... else ... end *)
  | While of expr * stmt list        (* while expr do ... end *)
  | Print of expr                    (* print expr *)
  | Input of string                  (* input var *)
  | Call of string * expr list       (* sink/sanitizer calls: call(name, args) *)

type program = stmt list
