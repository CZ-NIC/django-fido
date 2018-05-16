module.exports = {
    "env": {
        "browser": true,
        "es6": true,
        "node": true
    },
    "extends": "eslint:recommended",
    "parserOptions": {
        "sourceType": "module"
    },
    "rules": {
        // Basic settings
        "indent":               ["warn", 4],                // Indent with 4 spaces
        "no-tabs":              ["warn"],                   // Don't use tabs
        "no-trailing-spaces":   ["warn"],                   // Don't allow trailing spaces
        "linebreak-style":      ["error", "unix"],          // End lines with UNIX line breaks
        "max-len":              ["warn", { "code": 120 }],  // Line length is limited by 120 characters
        "semi":                 ["error", "never"],         // Don't use semicolons if not necessary
        "semi-style":           ["error", "first"],         // If necessary, write semicolon at the beginning of the line

        // Code settings
        "no-use-before-define": ["error"],                  // Define functions, classes and variables before you use them
        "no-var":               ["warn"],                   // Don't allow var
        "prefer-const":         ["warn", { "ignoreReadBeforeAssign": true }],  // If let is not assigned to, prefer const
        "no-return-assign":     ["error", "always"],        // Don't allow assingment in return statement
        "eqeqeq":               ["error", "smart"],         // Reqire use of === and !== instead of == and != (with a few exceptions)
        "complexity":           ["warn", 10],               // Maximum cyclomatic complexity

        // Spacing settings
        "keyword-spacing":      ["warn"],                   // Reqiure spacing around keywords
        "func-call-spacing":    ["error", "never"],         // Don't allow spaces between function call and arguments
        "space-before-function-paren": ["error", "never"],  // Don't allow spaces before function definition parenthesis
        "spaced-comment":       ["warn", "always"],         // Require whitespace after //
        "space-in-parens":      ["warn", "never"],          // Don't allow spaces in parenthesis
        "comma-spacing":        ["warn"],                   // Reqire space after comma, don't allow space before
        "space-infix-ops":      ["warn"],                   // Require spaces around infix operators (including =)
    }
};
