// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_QUALIFICATION_TRACE_INTERNAL_H
#define USK_QUALIFICATION_TRACE_INTERNAL_H
namespace usk::platform::windows {
// The optional native frontend composition registers before security admission.
class QualificationTrace final {
public:
    QualificationTrace() noexcept;
    ~QualificationTrace() noexcept;
    QualificationTrace(const QualificationTrace&) = delete;
    QualificationTrace& operator=(const QualificationTrace&) = delete;
private:
    bool owner_ = false;
    bool registered_ = false;
    bool enabled_ = false;
};
}
#endif
