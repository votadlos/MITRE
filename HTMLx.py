def html_table(th, data):

    return '<TABLE BORDER="1"><TR>{0}</TR><TR>{1}</TR></TABLE>'.format(
        '<TH ALIGN="CENTER">'+'</TH ALIGN="CENTER"><TH>'.join(str(j) for j in th)+'</TH></TR>',
        '</TR><TR>'.join(
            '<TD>{}</TD>'.format('</TD><TD>'.join(str(i) for i in row)) for row in data)
        )
