#if !canImport(Darwin)
import Foundation

// Foundation outside Apple platforms has no `String(localized:)` yet. This stand-in keeps the calls
// compiling there and gives the English text with its interpolations, untranslated. Apple platforms
// use Foundation's, with the translations in the app's Localizable.xcstrings.
extension String {
    package init(localized text: EnglishText, comment: StaticString? = nil) {
        self = text.value
    }
}

/// What the stand-in `String(localized:)` takes: a string literal, with interpolations.
package struct EnglishText: ExpressibleByStringInterpolation {
    let value: String

    package init(stringLiteral value: String) {
        self.value = value
    }

    package init(stringInterpolation: DefaultStringInterpolation) {
        value = String(stringInterpolation: stringInterpolation)
    }
}
#endif
