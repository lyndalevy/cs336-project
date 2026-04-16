(* lexer.ml — Simple lexer for IMP-Core *)

type token =
  | TNum of int
  | TIdent of string
  | TString of string
  | TAssign      (* := *)
  | TPlus | TMinus | TStar | TSlash
  | TEq | TNeq | TLt | TGt
  | TLParen | TRParen
  | TComma
  | TIf | TThen | TElse | TEnd
  | TWhile | TDo
  | TPrint
  | TInput
  | TEOF

let keywords = [
  ("if", TIf); ("then", TThen); ("else", TElse); ("end", TEnd);
  ("while", TWhile); ("do", TDo); ("print", TPrint); ("input", TInput);
]

let is_alpha c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
let is_digit c = c >= '0' && c <= '9'
let is_alnum c = is_alpha c || is_digit c || c = '_'

let tokenize (input : string) : token list =
  let len = String.length input in
  let pos = ref 0 in
  let tokens = ref [] in
  while !pos < len do
    let c = input.[!pos] in
    if c = ' ' || c = '\t' || c = '\n' || c = '\r' then
      incr pos
    else if c = '#' then begin
      (* skip line comments *)
      while !pos < len && input.[!pos] <> '\n' do incr pos done
    end
    else if c = ':' && !pos + 1 < len && input.[!pos + 1] = '=' then begin
      tokens := TAssign :: !tokens; pos := !pos + 2
    end
    else if c = '!' && !pos + 1 < len && input.[!pos + 1] = '=' then begin
      tokens := TNeq :: !tokens; pos := !pos + 2
    end
    else if c = '=' && !pos + 1 < len && input.[!pos + 1] = '=' then begin
      tokens := TEq :: !tokens; pos := !pos + 2
    end
    else if c = '+' then (tokens := TPlus :: !tokens; incr pos)
    else if c = '-' then (tokens := TMinus :: !tokens; incr pos)
    else if c = '*' then (tokens := TStar :: !tokens; incr pos)
    else if c = '/' then (tokens := TSlash :: !tokens; incr pos)
    else if c = '<' then (tokens := TLt :: !tokens; incr pos)
    else if c = '>' then (tokens := TGt :: !tokens; incr pos)
    else if c = '(' then (tokens := TLParen :: !tokens; incr pos)
    else if c = ')' then (tokens := TRParen :: !tokens; incr pos)
    else if c = ',' then (tokens := TComma :: !tokens; incr pos)
    else if c = '"' then begin
      incr pos;
      let start = !pos in
      while !pos < len && input.[!pos] <> '"' do incr pos done;
      let s = String.sub input start (!pos - start) in
      if !pos < len then incr pos;
      tokens := TString s :: !tokens
    end
    else if is_digit c then begin
      let start = !pos in
      while !pos < len && is_digit input.[!pos] do incr pos done;
      let n = int_of_string (String.sub input start (!pos - start)) in
      tokens := TNum n :: !tokens
    end
    else if is_alpha c then begin
      let start = !pos in
      while !pos < len && is_alnum input.[!pos] do incr pos done;
      let word = String.sub input start (!pos - start) in
      let tok = match List.assoc_opt word keywords with
        | Some t -> t
        | None -> TIdent word
      in
      tokens := tok :: !tokens
    end
    else begin
      Printf.eprintf "Lexer error: unexpected char '%c' at position %d\n" c !pos;
      incr pos
    end
  done;
  List.rev (TEOF :: !tokens)
