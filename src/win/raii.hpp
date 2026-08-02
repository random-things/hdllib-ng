#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <utility>

namespace hdl {
namespace win {

/* RAII HANDLE that CloseHandle's on destroy. Treats nullptr and INVALID_HANDLE_VALUE as empty. */
class unique_handle {
  public:
    unique_handle() = default;
    explicit unique_handle(HANDLE h) noexcept : h_(h) {}
    ~unique_handle() { reset(); }

    unique_handle(const unique_handle&) = delete;
    unique_handle& operator=(const unique_handle&) = delete;

    unique_handle(unique_handle&& o) noexcept : h_(o.release()) {}
    unique_handle& operator=(unique_handle&& o) noexcept {
        if (this != &o) {
            reset(o.release());
        }
        return *this;
    }

    HANDLE get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }

    HANDLE release() noexcept {
        HANDLE t = h_;
        h_ = nullptr;
        return t;
    }

    void reset(HANDLE h = nullptr) noexcept {
        if (h_ && h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
        }
        h_ = h;
    }

  private:
    HANDLE h_ = nullptr;
};

class unique_hmodule {
  public:
    unique_hmodule() = default;
    explicit unique_hmodule(HMODULE m) noexcept : m_(m) {}
    ~unique_hmodule() { reset(); }

    unique_hmodule(const unique_hmodule&) = delete;
    unique_hmodule& operator=(const unique_hmodule&) = delete;

    unique_hmodule(unique_hmodule&& o) noexcept : m_(o.release()) {}
    unique_hmodule& operator=(unique_hmodule&& o) noexcept {
        if (this != &o) {
            reset(o.release());
        }
        return *this;
    }

    HMODULE get() const noexcept { return m_; }
    explicit operator bool() const noexcept { return m_ != nullptr; }

    HMODULE release() noexcept {
        HMODULE t = m_;
        m_ = nullptr;
        return t;
    }

    void reset(HMODULE m = nullptr) noexcept {
        if (m_) {
            FreeLibrary(m_);
        }
        m_ = m;
    }

  private:
    HMODULE m_ = nullptr;
};

template <typename F> class scope_exit {
  public:
    explicit scope_exit(F&& f) : f_(std::forward<F>(f)), active_(true) {}
    ~scope_exit() {
        if (active_) {
            f_();
        }
    }
    scope_exit(const scope_exit&) = delete;
    scope_exit& operator=(const scope_exit&) = delete;
    scope_exit(scope_exit&& o) noexcept : f_(std::move(o.f_)), active_(o.active_) {
        o.active_ = false;
    }
    void release() noexcept { active_ = false; }

  private:
    F f_;
    bool active_;
};

template <typename F> scope_exit<F> make_scope_exit(F&& f) {
    return scope_exit<F>(std::forward<F>(f));
}

} // namespace win
} // namespace hdl
