#!/bin/zsh

mkdir -p ~/.zsh/completion
cp _autocc ~/.zsh/completion/_autocc
echo "fpath+=~/.zsh/completion \ autoload -Uz compinit \ compinit" >> ~/.zshrc
source .zshrc