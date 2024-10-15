#!/bin/bash

# Stage all changes, including untracked files
git add .

# Check if there are any staged changes
if git diff --cached --quiet; then
  echo "No changes to commit."
  exit 0
fi

# Copy the staged diff to the clipboard
git diff --cached | xclip -selection clipboard

# Read the clipboard and pass it to the Ollama command
commit_msg=$(xclip -selection clipboard -o | ollama run llama3.1:70b "Create a single line git commit message for this diff.  Your response should only contain the message and nothign else:")

# Commit the changes with the generated commit message
git commit -m "$commit_msg"

git push
