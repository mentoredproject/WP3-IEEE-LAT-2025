set terminal pngcairo enhanced font "arial,10" fontscale 1 size 1000, 1000
set output 'output.png'

# margins configuration
set lmargin 12.0
set tmargin 1.5

set style increment default
set grid lw 1
set style fill solid border -1
set style rect fc lt -1 fs solid 0.1 noborder

# set line styles: linecolor dashedtype pointtype pointsize linetype linewidth
set style line 1 lc rgb 'web-blue' dt "-" pt 6 lt 1 lw 1
set style line 2 lc rgb 'violet' dt 7 pt 12 lt 1 lw 3
set style line 3 lc rgb 'sea-green' dt 2 pt 2 lt 1 lw 1
set style line 4 lc rgb 'red' pt 4

set datafile missing '-'

# Graphic title
set title "Trafego de pacotes capturados no Servidor da Rede 1 com 5MB de memoria e 5m de CPU" font "Bold,14" offset 0,-1.2

# x axis configuration
set xtics border in scale 1,0.5 nomirror autojustify
set xtics 50
set xlabel "Time (s)" font "Bold,13" # offset 0,0.5
set xrange [ 0 : 700 ] noreverse writeback
set x2range [  :  ] noreverse writeback

# y axis configuration
set logscale y 2
set ytics 2 nomirror
set ylabel "Throughput (p/s)" font "Bold,13" offset 1.5
set yrange [ 1 : 20000 ] noreverse writeback
set y2range [  :  ] noreverse writeback

# other axis configuration
set zrange [  :  ] noreverse writeback
set cbrange [  :  ] noreverse writeback
set rrange [  :  ] noreverse writeback

# key/legend configuration
set key samplen 6 spacing 1.5 font ",12"

#Plot data
plot 'benign_iot_traffic.dat' using 1:2 title "IoT Traffic" w p ls 1, \
     'benign_servers_traffic.dat' using 1:2 title "Server Traffic" w p ls 2, \
     'malign_traffic.dat' using 1:2 title "malign Traffic" w p ls 4

#!display neigh_analysis.png
