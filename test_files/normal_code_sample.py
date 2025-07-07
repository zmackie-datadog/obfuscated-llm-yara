#!/usr/bin/env python3
"""
Simple calculator application
A basic Python script for mathematical operations
"""

import math
import sys

class Calculator:
    """A simple calculator class"""
    
    def __init__(self):
        self.history = []
    
    def add(self, a, b):
        """Add two numbers"""
        result = a + b
        self.history.append(f"{a} + {b} = {result}")
        return result
    
    def subtract(self, a, b):
        """Subtract b from a"""
        result = a - b
        self.history.append(f"{a} - {b} = {result}")
        return result
    
    def multiply(self, a, b):
        """Multiply two numbers"""
        result = a * b
        self.history.append(f"{a} * {b} = {result}")
        return result
    
    def divide(self, a, b):
        """Divide a by b"""
        if b == 0:
            raise ValueError("Cannot divide by zero")
        result = a / b
        self.history.append(f"{a} / {b} = {result}")
        return result
    
    def sqrt(self, x):
        """Calculate square root"""
        if x < 0:
            raise ValueError("Cannot calculate square root of negative number")
        result = math.sqrt(x)
        self.history.append(f"sqrt({x}) = {result}")
        return result
    
    def power(self, base, exponent):
        """Calculate base to the power of exponent"""
        result = math.pow(base, exponent)
        self.history.append(f"{base}^{exponent} = {result}")
        return result
    
    def get_history(self):
        """Return calculation history"""
        return self.history
    
    def clear_history(self):
        """Clear calculation history"""
        self.history = []

def main():
    """Main function to run the calculator"""
    calc = Calculator()
    
    print("Simple Calculator")
    print("Available operations: add, subtract, multiply, divide, sqrt, power")
    print("Type 'quit' to exit")
    
    while True:
        try:
            operation = input("\nEnter operation: ").strip().lower()
            
            if operation == 'quit':
                break
            elif operation == 'add':
                a = float(input("Enter first number: "))
                b = float(input("Enter second number: "))
                print(f"Result: {calc.add(a, b)}")
            elif operation == 'subtract':
                a = float(input("Enter first number: "))
                b = float(input("Enter second number: "))
                print(f"Result: {calc.subtract(a, b)}")
            elif operation == 'multiply':
                a = float(input("Enter first number: "))
                b = float(input("Enter second number: "))
                print(f"Result: {calc.multiply(a, b)}")
            elif operation == 'divide':
                a = float(input("Enter first number: "))
                b = float(input("Enter second number: "))
                print(f"Result: {calc.divide(a, b)}")
            elif operation == 'sqrt':
                x = float(input("Enter number: "))
                print(f"Result: {calc.sqrt(x)}")
            elif operation == 'power':
                base = float(input("Enter base: "))
                exp = float(input("Enter exponent: "))
                print(f"Result: {calc.power(base, exp)}")
            elif operation == 'history':
                history = calc.get_history()
                if history:
                    print("Calculation History:")
                    for item in history:
                        print(f"  {item}")
                else:
                    print("No history available")
            elif operation == 'clear':
                calc.clear_history()
                print("History cleared")
            else:
                print("Unknown operation")
                
        except ValueError as e:
            print(f"Error: {e}")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break

if __name__ == "__main__":
    main()