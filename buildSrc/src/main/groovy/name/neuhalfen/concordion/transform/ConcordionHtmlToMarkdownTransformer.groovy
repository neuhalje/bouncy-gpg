package name.neuhalfen.concordion.transform

class ConcordionHtmlToMarkdownTransformer extends FilterReader {
    ConcordionHtmlToMarkdownTransformer(Reader input) {
        super(transform(input))
    }

    static def transform(def reader) {
        def document = new XmlParser().parse(reader)
        def writer = new StringWriter()

        def body = document.body.get(0)
        def head = document.head.get(0)


        extractHeader(writer, head)
        extractBody(writer, body)

        return new StringReader(writer.toString())
    }


    static def extractHeader(StringWriter writer, def head) {
        writer.append("""+++
Xtitle = "XXXXXX"
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