reset

set terminal pngcairo size 500,400 enhanced font 'Arial,11'
set output 'eval1.png'

set border linewidth 1.1

# legend
set key top left

set style data histogram
set style histogram cluster gap 1
set style fill pattern border
set boxwidth 0.9
set xtic scale 0

set xlabel 'Topology size'
set ylabel 'Number of updates/revocation messages'


plot 'plotting_data.dat' using 2:xtic(1) ti 'SCION' lt -1, '' u 5 ti 'BGP' lt -1
