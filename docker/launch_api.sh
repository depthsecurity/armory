#!/bin/sh

session="main"

tmux start-server

tmux new-session -d -s $session

tmux send-keys "armory2-manage runserver 0.0.0.0:8099" C-m

tmux splitw -v -p 50

tmux send-keys "redis-server " C-m

tmux splitw -h -p 50

tmux send-keys "armory2-manage qcluster" C-m

tmux selectp -t 0

tmux splitw -h -p 50

tmux send-keys "echo 'Type \"tmux kill-server\" to tear it all down.'" C-m

tmux a