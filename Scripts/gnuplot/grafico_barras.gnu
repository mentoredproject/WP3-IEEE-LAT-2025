reset

#'offset' translada o rótulo sobre as coordenadas cartesianas x,y,z
set ylabel "{/:Bold Delay (s)}" offset 2.5,0,0

set yrange [0:3.9]
set xrange [1:69]

set xtics 10 nomirror
set ytics 0.5 nomirror
set border lw 3

#Definição das variáveis P e S com valores hexadecimais.
P = "#99d594"; S = "#fc8d59"

#Define o estilo da barra
#'set style fill { '' ou 'solid {<opacidade>}' ou 'pattern {<n>}'} {'border {<lt>}' ou 'noborder'}
#Em que '<opacidade>' recebe valor entre 0 e 1 e '<n>' recebe o número do padrão entre 0 e 7
set style fill solid 0.5 border lt -1

#Define o terminal para o formato png
set term png size 500, 300		#'size' determina as dimensões do arquivo de saída

set output "graf_barras.png"	#Cria o arquivo de saída no formato png

#É possível alterar o estilo do texto do título colocando-o entre '{/:{Bold ou Italic}:{'', Bold ou Italic} Nome do Título}' 
#'with boxes' define que vai ser gerado um gráfico de barras, ao contrário dos outros gráficos,
#nos gráficos de barras os parâmetros devem ser colocados após a definição do tipo do gráfico.
#'fs' (fill style) é similar a 'set style fill' e recebe os mesmos parâmetros
#'fc' (fill color) define a cor de preenchimento da barra e recebe uma string ("red", por exemplo) como parâmetro,
#ou pode utilizar o sistema de cores 'rgb'.

#'rgb' recebe valores em vários formatos. 
#Em formato hexadecimal: '#valor_hexadecimal' (caso dos conteúdos das variáveis P e S).
#E no próprio formato rgb: '(<n>, <n>, <n>)' em que <n> recebe valores entre 0 e 255 
#para as cores "red", "green" e "blue", respectivamente.

#'with yerrorbars' exibe o intervalo de confiança na vertical (eixo Y)
#'with xerrorbars' é similar ao 'yerrorbars', exibe o intervalo de confiaça na horizontal (eixo X)
plot 'graf_barras.dat' using 1:2:(3) title "{/:Bold POSSE-HWSN}" with boxes fs solid fc rgb P lw 2, \
	"" using ($1+3):3:(3) title "{/:Bold SACHSEN}" with boxes fs solid fc rgb S lw 2, \
	"" using 1:2:4 notitle with yerrorbars lt -1 lw 2, \
	"" using ($1+3):3:5 notitle with yerrorbars lt -1 lw 2

unset output					#Libera a escrita do arquivo de saída