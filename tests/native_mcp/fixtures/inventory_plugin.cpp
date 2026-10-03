#include "_plugins.h"
#include "bridgemain.h"
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QCompleter>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSettings>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QStringListModel>
#include <QTableView>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>
#include <memory>

namespace
{
    struct GuiActionRequest
    {
        QJsonObject fields;
        QString output;
        QString settings;
        DWORD commandThread;
    };

    void saveObservation(const QString& output, const QJsonObject& observation)
    {
        QSaveFile file(output);
        if(!file.open(QIODevice::WriteOnly))
            return;
        const auto content = QJsonDocument(observation).toJson(QJsonDocument::Indented);
        if(file.write(content) == content.size())
            file.commit();
    }

    QJsonObject modelValues(const QStandardItemModel& model)
    {
        return {{"counter", model.data(model.index(0, 0)).toInt()},
                {"label", model.data(model.index(0, 1)).toString()},
                {"enabled", model.data(model.index(0, 2)).toBool()}};
    }

    void exerciseGuiAction(void* context)
    {
        std::unique_ptr<GuiActionRequest> request(static_cast<GuiActionRequest*>(context));
        QJsonObject observation{{"schemaVersion", 1}, {"nonce", request->fields["nonce"]},
                                {"mode", request->fields["mode"]}, {"valid", false},
                                {"processId", QString::number(GetCurrentProcessId())},
                                {"commandThreadId", QString::number(request->commandThread)},
                                {"guiThreadId", QString::number(GetCurrentThreadId())},
                                {"ownerThread", QThread::currentThread() == qApp->thread()}};
        QMainWindow* window = nullptr;
        for(auto candidate : QApplication::topLevelWidgets())
            if(auto main = qobject_cast<QMainWindow*>(candidate))
                window = main;
        if(!window || QThread::currentThread() != qApp->thread())
        {
            observation["error"] = "GUI owner or main window unavailable";
            saveObservation(request->output, observation);
            return;
        }
        QSettings settings(request->settings, QSettings::IniFormat);
        settings.setIniCodec("UTF-8");
        QString storedLabel("initial");
        if(settings.contains("labelUtf16"))
        {
            const auto bytes = QByteArray::fromHex(settings.value("labelUtf16").toByteArray());
            storedLabel = QString::fromUtf16(reinterpret_cast<const ushort*>(bytes.constData()), bytes.size() / sizeof(ushort));
        }
        QStandardItemModel model(1, 3);
        model.setData(model.index(0, 0), settings.value("counter", 7).toInt());
        model.setData(model.index(0, 1), storedLabel);
        model.setData(model.index(0, 2), settings.value("enabled", false).toBool());
        observation["before"] = modelValues(model);
        QMenu menu("WBB GUI Fixture", window);
        menu.setObjectName("WbbGuiFixtureMenu");
        window->menuBar()->addMenu(&menu);
        auto action = menu.addAction("Edit fixture values");
        action->setObjectName("WbbGuiFixtureApply");
        action->setCheckable(true);
        int actionCalls = 0;
        QObject::connect(action, &QAction::triggered, &menu, [&](bool checked)
        {
            ++actionCalls;
            QDialog dialog(window);
            dialog.setObjectName("WbbGuiFixtureDialog");
            dialog.setWindowTitle("GUI action fixture");
            QVBoxLayout layout(&dialog);
            QSpinBox counter(&dialog);
            counter.setObjectName("FixtureCounter");
            counter.setRange(-4096, 4096);
            counter.setValue(model.data(model.index(0, 0)).toInt());
            QLineEdit label(model.data(model.index(0, 1)).toString(), &dialog);
            label.setObjectName("FixtureLabel");
            QCheckBox enabled("Enabled", &dialog);
            enabled.setObjectName("FixtureEnabled");
            enabled.setChecked(model.data(model.index(0, 2)).toBool());
            QTableView table(&dialog);
            table.setModel(&model);
            QDialogButtonBox buttons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
            layout.addWidget(&counter);
            layout.addWidget(&label);
            layout.addWidget(&enabled);
            layout.addWidget(&table);
            layout.addWidget(&buttons);
            int counterChanges = 0;
            int labelChanges = 0;
            int enabledChanges = 0;
            QObject::connect(&counter, static_cast<void(QSpinBox::*)(int)>(&QSpinBox::valueChanged), &dialog, [&](int) { ++counterChanges; });
            QObject::connect(&label, &QLineEdit::textChanged, &dialog, [&](const QString&) { ++labelChanges; });
            QObject::connect(&enabled, &QCheckBox::toggled, &dialog, [&](bool) { ++enabledChanges; });
            QObject::connect(&buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
            QObject::connect(&buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
            observation["actionChecked"] = checked;
            QTimer::singleShot(0, &dialog, [&]
            {
                observation["dialogVisible"] = dialog.isVisible();
                if(request->fields["mode"].toString() != "observe")
                {
                    counter.setValue(request->fields["counter"].toInt());
                    label.setText(request->fields["label"].toString());
                    enabled.setChecked(request->fields["enabled"].toBool());
                }
                observation["fields"] = QJsonObject{{"counter", counter.value()}, {"label", label.text()}, {"enabled", enabled.isChecked()}};
                observation["fieldSignals"] = QJsonObject{{"counter", counterChanges}, {"label", labelChanges}, {"enabled", enabledChanges}};
                buttons.button(request->fields["mode"].toString() == "apply" ? QDialogButtonBox::Ok : QDialogButtonBox::Cancel)->click();
            });
            const auto result = dialog.exec();
            observation["dialogResult"] = result;
            if(result == QDialog::Accepted)
            {
                model.setData(model.index(0, 0), counter.value());
                model.setData(model.index(0, 1), label.text());
                model.setData(model.index(0, 2), enabled.isChecked());
                settings.setValue("counter", counter.value());
                settings.setValue("enabled", enabled.isChecked());
                const auto text = label.text();
                const auto bytes = QByteArray(reinterpret_cast<const char*>(text.utf16()), text.size() * sizeof(ushort));
                settings.setValue("labelUtf16", QString::fromLatin1(bytes.toHex()));
                settings.sync();
            }
            observation["view"] = QJsonObject{{"rows", table.model()->rowCount()}, {"columns", table.model()->columnCount()},
                                              {"counter", table.model()->data(table.model()->index(0, 0)).toInt()},
                                              {"label", table.model()->data(table.model()->index(0, 1)).toString()},
                                              {"enabled", table.model()->data(table.model()->index(0, 2)).toBool()}};
        });
        action->trigger();
        observation["actionCalls"] = actionCalls;
        observation["actionId"] = action->objectName();
        observation["menuInstalled"] = window->menuBar()->actions().contains(menu.menuAction());
        observation["after"] = modelValues(model);
        observation["settingsStatus"] = int(settings.status());
        observation["valid"] = settings.status() == QSettings::NoError;
        window->menuBar()->removeAction(menu.menuAction());
        saveObservation(request->output, observation);
    }

    bool collectGuiAction(int count, char** arguments)
    {
        if(count != 2)
            return false;
        const QFileInfo input(QString::fromUtf8(arguments[1]));
        QFile file(input.absoluteFilePath());
        if(!file.open(QIODevice::ReadOnly) || file.size() < 2 || file.size() > 8192)
            return false;
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(file.readAll(), &error);
        auto request = std::make_unique<GuiActionRequest>();
        request->output = input.absolutePath() + "/" + input.completeBaseName() + ".result.json";
        request->settings = input.absolutePath() + "/gui-actions.ini";
        request->commandThread = GetCurrentThreadId();
        request->fields = document.object();
        const auto& fields = request->fields;
        const auto mode = fields["mode"].toString();
        const auto counter = fields["counter"].toDouble();
        const auto label = fields["label"].toString();
        if(error.error != QJsonParseError::NoError || !document.isObject() ||
           fields.size() != 5 || !fields["mode"].isString() ||
           !fields["counter"].isDouble() || counter < -4096 || counter > 4096 || counter != int(counter) ||
           !fields["enabled"].isBool() || !fields["label"].isString() || label.size() > 256 || label.contains(QChar(0)) ||
           !fields["nonce"].isString() || fields["nonce"].toString().isEmpty() || fields["nonce"].toString().size() > 64 ||
           (mode != "apply" && mode != "cancel" && mode != "observe"))
        {
            saveObservation(request->output, {{"schemaVersion", 1}, {"valid", false}, {"nonce", fields["nonce"]},
                                               {"error", "Invalid GUI fixture input"},
                                               {"processId", QString::number(GetCurrentProcessId())}});
            return false;
        }
        GuiExecuteOnGuiThreadEx(exerciseGuiAction, request.release());
        return true;
    }

    QString objectPath(const QObject* object)
    {
        QStringList parts;
        for(auto current = object; current; current = current->parent())
        {
            auto name = current->objectName();
            parts.prepend(QString::fromLatin1(current->metaObject()->className()) + ":" + name);
        }
        return parts.join("/");
    }

    QJsonObject actionDescription(const QAction* action)
    {
        return {{"objectName", action->objectName()}, {"text", action->text()},
                {"shortcut", action->shortcut().toString(QKeySequence::PortableText)},
                {"enabled", action->isEnabled()}, {"visible", action->isVisible()},
                {"checkable", action->isCheckable()}, {"separator", action->isSeparator()},
                {"owner", objectPath(action->parent())}};
    }

    void writeInventory(void* context)
    {
        std::unique_ptr<QString> output(static_cast<QString*>(context));
        QJsonArray menus;
        QJsonArray widgets;
        QJsonArray commands;
        QJsonArray scriptProviders;
        auto allWidgets = QApplication::allWidgets();
        if(allWidgets.size() > 16384)
            return;
        for(auto widget : allWidgets)
        {
            widgets.append(QJsonObject{{"class", QString::fromLatin1(widget->metaObject()->className())},
                                       {"objectName", widget->objectName()}, {"path", objectPath(widget)},
                                       {"enabled", widget->isEnabled()}, {"visible", widget->isVisible()}});
            if(auto menu = qobject_cast<QMenu*>(widget))
            {
                QJsonArray actions;
                for(auto action : menu->actions())
                    actions.append(actionDescription(action));
                menus.append(QJsonObject{{"title", menu->title()}, {"path", objectPath(menu)}, {"actions", actions}});
            }
            if(auto selector = qobject_cast<QComboBox*>(widget))
            {
                if(selector->parent() && selector->parent()->objectName() == "cmdBar")
                    for(int index = 0; index < selector->count(); ++index)
                        scriptProviders.append(selector->itemText(index));
            }
            if(QString::fromLatin1(widget->metaObject()->className()) != "CommandLineEdit")
                continue;
            auto editor = qobject_cast<QLineEdit*>(widget);
            if(!editor || !editor->completer())
                continue;
            if(!QMetaObject::invokeMethod(editor, "autoCompleteUpdate", Qt::DirectConnection, Q_ARG(QString, QString("baseline"))))
                continue;
            auto model = editor->completer()->model();
            for(int row = 0; row < model->rowCount(); ++row)
                commands.append(model->data(model->index(row, 0), Qt::DisplayRole).toString());
            QMetaObject::invokeMethod(editor, "autoCompleteUpdate", Qt::DirectConnection, Q_ARG(QString, editor->text()));
        }
        const auto debugging = DbgIsDebugging();
        const auto runLockUnlocked = DbgIsRunning();
        QJsonObject inventory{{"schemaVersion", 2}, {"processId", QString::number(GetCurrentProcessId())},
                              {"guiThreadId", QString::number(GetCurrentThreadId())},
                              {"menus", menus}, {"widgets", widgets}, {"commands", commands},
                              {"debugState", QJsonObject{{"debugging", debugging}, {"running", debugging && runLockUnlocked}}},
                              {"runLockUnlocked", runLockUnlocked},
                              {"scriptProviders", scriptProviders}};
        QSaveFile file(*output);
        if(file.open(QIODevice::WriteOnly))
        {
            auto content = QJsonDocument(inventory).toJson(QJsonDocument::Indented);
            if(file.write(content) == content.size())
                file.commit();
        }
    }

    bool collectInventory(int count, char** arguments)
    {
        if(count != 2)
            return false;
        auto output = std::make_unique<QString>(QString::fromUtf8(arguments[1]));
        GuiExecuteOnGuiThreadEx(writeInventory, output.release());
        return true;
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    init->sdkVersion = PLUG_SDKVERSION;
    init->pluginVersion = 1;
    strcpy_s(init->pluginName, "Baseline Inventory Fixture");
    return _plugin_registercommand(init->pluginHandle, "baselineinventory", collectInventory, false) &&
           _plugin_registercommand(init->pluginHandle, "baselineguiactions", collectGuiAction, false);
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}

extern "C" __declspec(dllexport) bool plugstop()
{
    return true;
}
