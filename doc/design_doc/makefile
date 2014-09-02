PAPER = 0-manual
LATEX = latex
DVIPS = dvips
DVIPDF = dvipdf
BIBTEX = bibtex

TEXFILES = $(shell ls *.tex *.bib)

$(PAPER).pdf: $(PAPER).ps
	ps2pdf -dCompatibilityLevel=1.3 $(PAPER).ps $(PAPER).pdf
	
pdf: $(PAPER).pdf
	
: $(PAPER).pdf

ps: $(PAPER).ps

$(PAPER).ps: $(TEXFILES)
	$(LATEX) $(PAPER)
	$(BIBTEX) $(PAPER)
	$(LATEX) $(PAPER)
	$(LATEX) $(PAPER)
	$(DVIPS) -K -Ppdf -G0 -t letter -o $(PAPER).ps $(PAPER).dvi


mate:
	pdflatex -synctex=1 $(PAPER)

clean:
	rm -f $(PAPER).ps $(PAPER).pdf *~ *.dvi *.log *.aux *.blg *.bbl *.toc *.backup *.bak

tar:
	tar -cvzf $(PAPER).taz *.tex *.bib makefile *.eps *.ai
