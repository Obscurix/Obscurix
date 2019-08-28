#
# ~/.bash_profile
#

[[ -f ~/.bashrc ]] && . ~/.bashrc


if [[ ! $DISPLAY && $XDG_VTNR -eq 1 ]]; then
  exec startx -- -keeptty &> /dev/null 2>&1
fi
