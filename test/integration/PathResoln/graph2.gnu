reset

set terminal pngcairo size 500,400 enhanced font 'Arial,11'
set output 'eval2.png'

# legend
set key top left

set style data histogram
set style histogram cluster gap 1
set style fill pattern border
set boxwidth 0.9
set xtic scale 0

set xlabel 'Topology size'
set ylabel 'Number of revocation messages'

plot 'plotting_data.dat' u 2:xtic(1) ti '1 sec' lt -1, '' u 3 ti '2 sec' lt -1, '' u 4 title '5 sec' lt -1
