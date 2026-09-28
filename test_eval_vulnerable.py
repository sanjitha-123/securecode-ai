import ast
import operator

operators = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

def safe_eval(node):
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, complex)):
            return node.value
        raise ValueError("Unsupported literal type")
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type in operators:
            return operators[op_type](safe_eval(node.left), safe_eval(node.right))
        raise ValueError("Unsupported operator")
    elif isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type in operators:
            return operators[op_type](safe_eval(node.operand))
        raise ValueError("Unsupported operator")
    raise ValueError("Unsupported expression")

user_input = input("Enter expression: ")

tree = ast.parse(user_input, mode='eval')
result = safe_eval(tree)

print("Result:", result)