#pragma once

#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>

// Non-owning callable reference, used for the byte sinks and sources that the
// cpio and compression code takes.
//
// std::function was the obvious spelling but it pays for ownership nobody here
// wants: it heap-allocates whenever the callable is larger than libc++'s small
// buffer (three pointers, which several of these capture-by-reference lambdas
// exceed), and instantiating it emits a type_info plus target()/target_type()
// machinery per distinct callable. This is two pointers, trivially copyable,
// allocation-free, and RTTI-free.
//
// The trade: it does not extend the callable's lifetime. Every parameter typed
// with it is consumed before the call returns, so binding a temporary lambda in
// the argument list is fine. Storing one in a variable is only safe when the
// callable it refers to is itself a named object that outlives it.
template <typename Signature>
class FunctionRef;

template <typename Result, typename... Args>
class FunctionRef<Result(Args...)> {
public:
    FunctionRef() = default;
    FunctionRef(std::nullptr_t) noexcept {}

    template <typename Callable,
              typename = std::enable_if_t<
                  !std::is_same_v<std::decay_t<Callable>, FunctionRef> &&
                  std::is_invocable_r_v<Result, std::remove_reference_t<Callable>&, Args...>>>
    FunctionRef(Callable&& callable) noexcept
        : object_(const_cast<void*>(static_cast<const void*>(std::addressof(callable)))),
          invoke_([](void* object, Args... args) -> Result {
              return (*static_cast<std::remove_reference_t<Callable>*>(object))(
                  std::forward<Args>(args)...);
          }) {}

    Result operator()(Args... args) const { return invoke_(object_, std::forward<Args>(args)...); }

    [[nodiscard]] explicit operator bool() const noexcept { return invoke_ != nullptr; }

private:
    void* object_ = nullptr;
    Result (*invoke_)(void*, Args...) = nullptr;
};
