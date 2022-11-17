#!bin/bash

if [ ${__UTILS_SH__} ]; then
    exit 0
fi
__UTILS_SH__=1

################################################################

color_black="\033[1;30m"
color_red="\033[1;31m"
color_green="\033[1;32m"
color_yellow="\033[1;33m"
color_blue="\033[1;34m"
color_purple="\033[1;35m"
color_skyblue="\033[1;36m"
color_white="\033[1;37m"
color_gray="\033[1;90m"
color_reset="\033[0m"
echo_line() {
    printf "$color_gray[$1$2$color_gray]$color_reset $3\n"
}
echo_r() {
    echo_line $color_green "*" "$1"
    eval $1
}
echo_i() {
    echo_line $color_white "i" "$1"
}
echo_w() {
    echo_line $color_yellow "?" "$1"
}
echo_e() {
    echo_line $color_red "!" "$1"
}
