#include "_plugins.h"
#include "bridgemain.h"
#include <QAction>
#include <QApplication>
#include <QComboBox>
#include <QCompleter>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QMenu>
#include <QSaveFile>
#include <QStringListModel>
#include <memory>

namespace
{
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
    return _plugin_registercommand(init->pluginHandle, "baselineinventory", collectInventory, false);
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}

extern "C" __declspec(dllexport) bool plugstop()
{
    return true;
}
