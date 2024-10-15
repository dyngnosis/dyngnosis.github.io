#!/bin/bash

# Stage all changes (including new and modified files)
git add .

# Check for any staged changes
if git diff --cached --quiet; then
  echo "No changes to commit."
  exit 0
fi

# Generate the commit message using Ollama
commit_msg=$(git diff | ollama run llama3.1:70b "Create a gitcommit message for this diff:")

# Commit the changes with the generated message
git commit -m "$commit_msg"

