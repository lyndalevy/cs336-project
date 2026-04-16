(* parser.ml — Recursive descent parser for IMP-Core *)

open Ast
open Lexer

type parser_state = {
  mutable tokens : token list;
  mutable line : int;
}

let make_parser tokens = { tokens; line = 1 }

let peek ps = match ps.tokens with
  | [] -> TEOF
  | t :: _ -> t

let advance ps = match ps.tokens with
  | [] -> TEOF
  | t :: rest -> ps.tokens <- rest; t

let expect ps tok =
  let t = advance ps in
  if t <> tok then
    Printf.eprintf "Parse error at line %d: expected %s\n" ps.line "token"

let parse_op ps =
  match advance ps with
  | TPlus -> Add | TMinus -> Sub | TStar -> Mul | TSlash -> Div
  | TEq -> Eq | TNeq -> Neq | TLt -> Lt | TGt -> Gt
  | _ -> failwith (Printf.sprintf "Parse error at line %d: expected operator" ps.line)

let rec parse_atom ps =
  match peek ps with
  | TNum _ ->
    let t = advance ps in
    (match t with TNum n -> Num n | _ -> assert false)
  | TIdent _ ->
    let t = advance ps in
    (match t with TIdent v -> Var v | _ -> assert false)
  | TString _ ->
    let t = advance ps in
    (match t with TString _ -> Num 0 | _ -> assert false)
  | TLParen ->
    ignore (advance ps);
    let e = parse_expr ps in
    expect ps TRParen;
    e
  | _ -> failwith (Printf.sprintf "Parse error at line %d: expected expression" ps.line)

and parse_expr ps =
  let left = parse_atom ps in
  match peek ps with
  | TPlus | TMinus | TStar | TSlash | TEq | TNeq | TLt | TGt ->
    let op = parse_op ps in
    let right = parse_atom ps in
    BinOp (op, left, right)
  | _ -> left

let rec parse_args ps =
  match peek ps with
  | TRParen -> []
  | _ ->
    let e = parse_expr ps in
    match peek ps with
    | TComma -> ignore (advance ps); e :: parse_args ps
    | _ -> [e]

let rec parse_stmt ps =
  match peek ps with
  | TIdent name -> begin
    ignore (advance ps);
    match peek ps with
    | TAssign ->
      ignore (advance ps);
      let e = parse_expr ps in
      Assign (name, e)
    | TLParen ->
      (* function call: name(args) — treated as sink/sanitizer *)
      ignore (advance ps);
      let args = parse_args ps in
      expect ps TRParen;
      Call (name, args)
    | _ -> failwith (Printf.sprintf "Parse error: unexpected token after '%s'" name)
    end
  | TIf ->
    ignore (advance ps);
    let cond = parse_expr ps in
    expect ps TThen;
    let then_body = parse_stmts ps in
    let else_body = match peek ps with
      | TElse -> ignore (advance ps); parse_stmts ps
      | _ -> []
    in
    expect ps TEnd;
    If (cond, then_body, else_body)
  | TWhile ->
    ignore (advance ps);
    let cond = parse_expr ps in
    expect ps TDo;
    let body = parse_stmts ps in
    expect ps TEnd;
    While (cond, body)
  | TPrint ->
    ignore (advance ps);
    let e = parse_expr ps in
    Print e
  | TInput ->
    ignore (advance ps);
    let t = advance ps in
    (match t with
     | TIdent v -> Input v
     | _ -> failwith "Parse error: expected variable after 'input'")
  | t -> failwith (Printf.sprintf "Parse error: unexpected token in statement: %s"
    (match t with TIdent s -> s | _ -> "?"))

and parse_stmts ps =
  let stmts = ref [] in
  let stop = ref false in
  while not !stop do
    match peek ps with
    | TElse | TEnd | TEOF -> stop := true
    | _ ->
      let s = parse_stmt ps in
      stmts := s :: !stmts
  done;
  List.rev !stmts

let parse (input : string) : program =
  let tokens = tokenize input in
  let ps = make_parser tokens in
  parse_stmts ps
