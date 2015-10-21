#!/usr/bin/gnuplot
#
# Plotting the data of file plotting_data1.dat
#
# AUTHOR: Hagen Wierstorf

reset

# wxt
#set terminal wxt size 350,262 enhanced font 'Verdana,10' persist
# png
set terminal pngcairo size 500,400 enhanced font 'Verdana,10'
set output 'plotting_data.png'
# svg
#set terminal svg size 350,262 fname 'Verdana, Helvetica, Arial, sans-serif' \
#fsize '10'
#set output 'plotting_data1.svg'

# color definitions
set border linewidth 0.5
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 0.5 # --- blue

unset key

set xlabel 'Topology size' 
set ylabel 'Number of messages'
set title "Number of messages received for increasing topologies"

plot 'plotting_data.dat' using 1:2 with lines, \
	 'plotting_data.dat' using 1:3 with lines, \
	 'plotting_data.dat' using 1:4 with lines, \
	 'plotting_data.dat' using 1:5 with lines