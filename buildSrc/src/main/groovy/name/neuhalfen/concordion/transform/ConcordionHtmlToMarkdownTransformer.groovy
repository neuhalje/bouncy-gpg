package name.neuhalfen.concordion.transform

class ConcordionHtmlToMarkdownTransformer extends FilterReader {
    ConcordionHtmlToMarkdownTransformer(Reader input) {
        super(transform(input))
    }

    static def transform(def reader) {
        def document = new XmlParser().parse(reader)
        def writer = new StringWriter()

        def body = document.body.get(0)


        extractHeader(writer, document)
        extractBody(writer, body)

        return new StringReader(writer.toString())
    }


    static def extractHeader(StringWriter writer, def html) {
        def head = html.head.get(0)
        def title = head.title[0]?.text()
        if (!title){
             title = html.body.h1[0]?.text()
        }

        writer.append("""+++
title = "$title"
Xdescription = "YYYYY"
tags = [
    "specification",
    "development"
]
categories = [
    "Development"
]
menu = "Specifications"
+++

""")
    }

    static def extractBody(StringWriter writer, def body) {
        def indentPrinter = new IndentPrinter(writer, "",false,false)
        def xmlNodePrinter = new XmlNodePrinter(indentPrinter)

        body.children().each {
            xmlNodePrinter.print(it)
        }
    }


}