package name.neuhalfen.concordion.transform

class ConcordionHtmlToMarkdownTransformer extends FilterReader {
    ConcordionHtmlToMarkdownTransformer(Reader input) {
        super(transform(input))
    }

    static def transform(def reader) {
        def document = new XmlParser().parse(reader)
        def writer = new StringWriter()

        def body = document.body.get(0)

        extractSlug(writer, document)
        extractBody(writer, body)

        return new StringReader(writer.toString())
    }

    static def isTOMLFrontMatter(frontMatter) {
        return frontMatter.startsWith("+++") && frontMatter.endsWith("+++")
    }
    static def isYAMLFrontMatter(frontMatter) {
        return frontMatter.startsWith("---") && frontMatter.endsWith("---")
    }
    static def isJSONFrontMatter(frontMatter) {
        return frontMatter.startsWith("{") && frontMatter.endsWith("}")
    }
    static def extractSlug(StringWriter writer, Node document) {

        def body = document.body.get(0)
        def slugNode = body.p[0]

        def slug
        if (slugNode) {
            def nodeText = slugNode.text()
            if  ( isJSONFrontMatter(nodeText)) {
                slugNode.parent().remove(slugNode)
                slug = nodeText
            }
        }
        if (slug) {
            writer.append(slug).append("\n")
        } else {
            extractHeader(writer, document)
        }
    }

    static def extractHeader(StringWriter writer, Node html) {
        def head = html.head.get(0)
        def title = head.title[0]?.text()


        if (!title) {
            def h1 = html.body.h1[0]
            if (h1) {
                title = h1.text()

                // remove the source of the title bc. the CMS will taker care of providing it
                h1.parent().remove(h1)
            }
        }


        writer.append("""+++
title = "$title"
linktitle = "$title"
tags = [
    "specification",
    "development"
]
categories = [
    "API"
]
+++

""")
    }

    static def extractBody(StringWriter writer, def body) {
        def indentPrinter = new IndentPrinter(writer, "", false, false)
        def xmlNodePrinter = new XmlNodePrinter(indentPrinter)

        body.children().each {
            xmlNodePrinter.print(it)
        }
    }


}
