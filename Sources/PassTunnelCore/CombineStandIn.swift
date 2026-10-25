#if !canImport(Combine)
import Foundation

// Combine is an Apple framework. Where it is missing (Linux), this stand-in gives Core and the CLI the
// few parts they use, under the same names and with the same behavior: `ObservableObject`, `@Published`
// (its publisher sends the current value to a new subscriber, then every new value before it is
// stored), `PassthroughSubject`, `compactMap`, `sink`, `AnyCancellable` and `store(in:)`. Not
// thread-safe: like the code using it, call it on one actor (the main one). The Mac uses Combine.

/// Marks a type whose state is `@Published` (no `objectWillChange` here: nothing observes it).
public protocol ObservableObject: AnyObject {}

/// Ends a subscription when cancelled or released.
public final class AnyCancellable: Hashable {
    private var onCancel: (() -> Void)?

    public init(_ cancel: @escaping () -> Void) {
        onCancel = cancel
    }

    deinit { cancel() }

    public func cancel() {
        let action = onCancel
        onCancel = nil
        action?()
    }

    public func store(in set: inout Set<AnyCancellable>) {
        set.insert(self)
    }

    public static func == (a: AnyCancellable, b: AnyCancellable) -> Bool { a === b }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }
}

/// A stream of values; this stand-in never fails one (`Failure` is always `Never`).
public struct AnyPublisher<Output, Failure: Error> {
    /// Subscribes `receive` to the values and returns what ends the subscription.
    let subscribe: (@escaping (Output) -> Void) -> AnyCancellable

    public func sink(receiveValue: @escaping (Output) -> Void) -> AnyCancellable {
        subscribe(receiveValue)
    }

    /// The non-nil results of `transform`.
    public func compactMap<T>(_ transform: @escaping (Output) -> T?) -> AnyPublisher<T, Failure> {
        let subscribe = self.subscribe
        return AnyPublisher<T, Failure> { receive in
            subscribe { value in
                if let result = transform(value) { receive(result) }
            }
        }
    }
}

/// The subscribers of one publisher, in the order they subscribed.
final class Subscribers<Output> {
    private var handlers: [(id: Int, receive: (Output) -> Void)] = []
    private var lastID = 0

    func add(_ receive: @escaping (Output) -> Void) -> AnyCancellable {
        lastID += 1
        let id = lastID
        handlers.append((id, receive))
        return AnyCancellable { [weak self] in self?.handlers.removeAll { $0.id == id } }
    }

    /// To the subscribers there are when it starts (a subscriber may cancel while it runs).
    func send(_ value: Output) {
        for handler in handlers { handler.receive(value) }
    }
}

/// Sends what it is given to its subscribers at that moment.
public final class PassthroughSubject<Output, Failure: Error> {
    private let subscribers = Subscribers<Output>()

    public init() {}

    public func send(_ value: Output) {
        subscribers.send(value)
    }

    public func sink(receiveValue: @escaping (Output) -> Void) -> AnyCancellable {
        subscribers.add(receiveValue)
    }
}

/// A property whose changes can be subscribed to through `$property`.
@propertyWrapper
public struct Published<Value> {
    private final class Storage {
        var value: Value
        let subscribers = Subscribers<Value>()

        init(_ value: Value) {
            self.value = value
        }
    }

    private let storage: Storage

    public init(wrappedValue: Value) {
        storage = Storage(wrappedValue)
    }

    public var wrappedValue: Value {
        get { storage.value }
        nonmutating set {
            // Before the value is stored, as Combine's `@Published` does (in `willSet`).
            storage.subscribers.send(newValue)
            storage.value = newValue
        }
    }

    /// The current value at once, then every new one.
    public var projectedValue: AnyPublisher<Value, Never> {
        let storage = self.storage
        return AnyPublisher { receive in
            receive(storage.value)
            return storage.subscribers.add(receive)
        }
    }
}
#endif
