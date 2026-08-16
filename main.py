"""
Main Entry Point for Password Strength Checker
Options:
  python main.py          -> Starts Web GUI Dashboard (Flask)
  python main.py --cli    -> Starts Interactive CLI Tool
"""

import sys
import os

if __name__ == "__main__":
    if "--cli" in sys.argv or "-c" in sys.argv:
        from cli import interactive_cli
        interactive_cli()
    else:
        from app import app
        print("=========================================================")
        print("  🔐 PASSWORD STRENGTH ANALYZER WEB DASHBOARD")
        print("=========================================================")
        print("  Running locally on: http://127.0.0.1:5000")
        print("  Press Ctrl+C to stop the server.")
        print("  (Tip: Run 'python main.py --cli' for terminal mode)")
        print("=========================================================")
        app.run(host="127.0.0.1", port=5000, debug=True)
