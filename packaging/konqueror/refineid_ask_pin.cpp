// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <QApplication>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QIcon>
#include <iostream>
#include <string>

class PinDialog : public QDialog {
public:
    PinDialog(const QString &prompt) {
        setWindowTitle(QStringLiteral("RefineID Smart Card"));
        setWindowIcon(QIcon::fromTheme(QStringLiteral("dialog-password")));
        setFixedSize(380, 160);
        setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);

        QVBoxLayout *layout = new QVBoxLayout(this);
        layout->setContentsMargins(18, 18, 18, 18);
        layout->setSpacing(12);

        QLabel *label = new QLabel(prompt, this);
        label->setWordWrap(true);
        layout->addWidget(label);

        m_edit = new QLineEdit(this);
        m_edit->setEchoMode(QLineEdit::Password);
        m_edit->setPlaceholderText(QStringLiteral("PIN 1"));
        layout->addWidget(m_edit);

        QHBoxLayout *bl = new QHBoxLayout();
        bl->addStretch();
        m_cancel = new QPushButton(QStringLiteral("Cancel"), this);
        m_ok = new QPushButton(QStringLiteral("OK"), this);
        m_cancel->setAutoDefault(false);
        m_ok->setAutoDefault(false);
        m_ok->setDefault(true);
        bl->addWidget(m_cancel);
        bl->addWidget(m_ok);
        layout->addLayout(bl);

        connect(m_ok, &QPushButton::clicked, this, &PinDialog::onOk);
        connect(m_cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(m_edit, &QLineEdit::returnPressed, this, &PinDialog::onOk);

        m_edit->setFocus();
    }

    void onOk() {
        if (!m_edit->text().isEmpty()) {
            accept();
        }
    }

    QLineEdit *m_edit;
    QPushButton *m_ok;
    QPushButton *m_cancel;
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QString prompt = (argc > 1) ? QString::fromUtf8(argv[1]) : QStringLiteral("Please enter PIN 1 (Authentication):");
    PinDialog dlg(prompt);
    if (dlg.exec() == QDialog::Accepted) {
        std::string s = dlg.m_edit->text().toStdString();
        if (!s.empty()) {
            std::cout << s << std::endl;
            for (size_t i = 0; i < s.length(); i++) s[i] = 0;
            return 0;
        }
    }
    return 1;
}
