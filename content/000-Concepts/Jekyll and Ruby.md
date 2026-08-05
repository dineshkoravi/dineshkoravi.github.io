---
publish: true
created: 2026-01-24T16:14:55.893+05:30
modified: 2026-06-23T12:16:05.420+05:30
---

This is related to my github blog.

```
(install ruby from github sometimes as apt does not have latest version)


# install ruby via rbenv from here : https://github.com/rbenv/rbenv
$ git clone https://github.com/rbenv/rbenv.git ~/.rbenv
$ ~/.rbenv/bin/rbenv init
$ echo 'eval "$(rbenv init -)"' >> ~/.zshrc
$ git clone https://github.com/rbenv/ruby-build.git "$(rbenv root)"/plugins/ruby-build
$ rbenv install 3.3.6
$ rbenv global 3.3.6
$ export PATH="$HOME/.rbenv/bin:$PATH"

# below lines must exists in bashrc or zshrc
# export PATH="$HOME/.rbenv/bin:$PATH"
# eval "$(rbenv init -)"

install libyaml-dev
bundle config set --local path 'vendor/bundle'
bundle install
gem install bundler jekyll
bundle exec jekyll serve
```

Upgrading Chirpy to latest

```
git remote add upstream https://github.com/cotes2020/chirpy-starter.git
git fetch upstream
git tag
git merge v5.3.0 --allow-unrelated-histories
solve all the conflits in vscode editor
git status
git commit

```
