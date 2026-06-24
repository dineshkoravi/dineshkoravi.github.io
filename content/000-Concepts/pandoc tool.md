---
publish: true
created: 2026-02-06T17:48:41.166+05:30
modified: 2026-06-24T17:22:47.476+05:30
---

### Pandoc

disable float for images and keep subtext - <https://stackoverflow.com/a/58840456>

```
$ cat disable_float.tex 
\usepackage{float}
\let\origfigure\figure
\let\endorigfigure\endfigure
\renewenvironment{figure}[1][2] {
    \expandafter\origfigure\expandafter[H]
} {
    \endorigfigure
}
```

and mark images as.

```
![text](OSCP-exam-report-template_dinesh/IMG.png)

# optional {width=300px height=200px}
```

shell highlights - <https://stackoverflow.com/a/66953455> - optional

original command

```
$ pandoc OSCP-exam-report-template_dinesh.md \
-o output/OSCP-OS-XXXXX-Exam-Report.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel \
--table-of-contents \
--toc-depth 6 \
--number-sections \
--top-level-division=chapter \
--syntax-highlighting breezedark \
--resource-path=.:src
```

```
pandoc OSCP-exam-report-template_dinesh.md -o output/OSCP-OS-5xxxx-Exam-Report.pdf --from markdown+yaml_metadata_block+raw_html --template eisvogel --table-of-contents --toc-depth 6 --number-sections --top-level-division=chapter --syntax-highlighting breezedark --resource-path=.:src -H disable_float.tex
```
