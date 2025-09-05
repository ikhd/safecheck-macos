# Contributing to SafeCheck Pro (macOS)

Thank you for considering contributing! 🎉

---

## 🧭 General Rules
- Do **not** add destructive commands (e.g., `rm -rf`).  
- New features must be **opt-in** via configuration flags or variables.  
- Keep compatibility with macOS (preferably 12+).  
- Add clear comments for any new indicators or logic.  

---

## ⚙️ Local Setup
1. Clone the repo:
   ```bash
   git clone https://github.com/ikhd/safecheck-macos.git
   cd safecheck-macos
   ```

2. Make the script executable:
   ```bash
   chmod +x SafeCheck_Pro.sh
   ```
   
3. Run for testing:
   ```bash
   ./SafeCheck_Pro.sh
   ```

---

## 📝 Code Style

Run ShellCheck before submitting:
   ```bash
shellcheck SafeCheck_Pro.sh
   ```

- Use shfmt for formatting if available.

---

## 🔀 Pull Requests

- Clearly describe the problem your change solves.

- Add example output if relevant.

- Update README.md if you add or modify options.

---

## 🙏 Ways to Contribute

- Add new indicators.

- Improve performance or compatibility.

- Fix bugs.

- Enhance documentation.
