PAPERNAME=document

$(PAPERNAME).pdf: *.tex
	pdflatex $(PAPERNAME)
	# bibtex --min-crossrefs=100 $(PAPERNAME)
	pdflatex $(PAPERNAME)
	pdflatex $(PAPERNAME)


mate: *.tex
	pdflatex -synctex=1 -interaction nonstopmode $(PAPERNAME)
	bibtex --min-crossrefs=100 $(PAPERNAME)


full: *.tex 
	latex -synctex=1 $(PAPERNAME)
	#bibtex --min-crossrefs=100 $(PAPERNAME)
	latex -synctex=1 $(PAPERNAME)
	latex -synctex=1 $(PAPERNAME)
	dvips -Ppdf -G0 -t letter -o $(PAPERNAME).ps $(PAPERNAME)
	ps2pdf -dCompatibilityLevel=1.3 $(PAPERNAME).ps


force:
	rm -f $(PAPERNAME).pdf
	make


clean:
	rm -f $(PAPERNAME).ps $(PAPERNAME).pdf *.dvi *.aux *.log *.blg *.bbl *~
