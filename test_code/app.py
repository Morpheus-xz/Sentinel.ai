import os
from utils import calculate_sum

# 1. STATIC SCANNER TARGETS (Secrets & PII)
api_key = "sk-9876543210abcdef"
student_email = "vedansh@example.com"
student_phone = "555-123-4567"


# 2. AST SEMANTIC SCANNER TARGET
# The AST parser will extract this entire function as one logical block
# and send it to CodeBERT to calculate the math similarity.
def execute_dynamic_code(user_payload):
    return eval(user_payload)


def process_data():
    user_payload = input("Enter your math equation: ")

    # Passing the payload into our vulnerable AST block
    result = execute_dynamic_code(user_payload)

    print(f"Result: {result}")


if __name__ == "__main__":
    process_data()