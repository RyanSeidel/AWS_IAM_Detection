# AWS_IAM_Detection
A group project for Cloud Computing that involves with detecting IAM permissions


# Github commands to know 


# How to go to your branch

git branch - To check what branch you are on

git checkout your-branch-name - To go to your branch
git pull origin your-branch-name - To get the latest version of your branch

git status

# If you want to merge a branch into your branch
git pull origin (branch) - The name of the branch you want
git merge (branch) - Merge the branch into your branch

git push origin ( your branch name )


# How to save changes and push
git add .
git commit -m "Clear description"
git push origin your-branch-name


git push origin your-branch-name
git status  # Should say "nothing to commit"

# How to read about other branches

# Local branches only
git branch

# Remote branches (on GitHub)
git branch -r

# ALL branches (local + remote)
git branch -a

# See what's on ryan-dev
git log origin/ryan-dev --oneline -10 - This is an example, just change the name of branch
