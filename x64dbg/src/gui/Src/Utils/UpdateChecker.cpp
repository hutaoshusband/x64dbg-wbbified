#include "UpdateChecker.h"
#include <QMessageBox>
#include <QIcon>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <Gui/ReleaseNotesDialog.h>

#include "StringUtil.h"
#include "MiscUtil.h"

// Update checks are permanently disabled in this build: the debugger must not
// contact any external server, so no update URL is compiled in.

UpdateChecker::UpdateChecker(QWidget* parent)
    : QThread(parent)
    , mParent(parent)
    , mUserAgent("WinInspect " + ToDateString(GetCompileDate()) + " " __TIME__)
{
    connect(this, &UpdateChecker::updateCheckFinished, this, &UpdateChecker::finishedSlot);

    auto downloadFn = [](const QString & url) -> QImage
    {
        Q_UNUSED(url);
        return {};
    };
    mReleaseNotes = new ReleaseNotesDialog(downloadFn, mParent);
    mReleaseNotes->setWindowIcon(DIcon("bug"));
}

void UpdateChecker::checkForUpdates()
{
    GuiAddStatusBarMessage(tr("Update checks are disabled in this build.\n").toUtf8().constData());
}

void UpdateChecker::run()
{
    emit updateCheckFinished(QString());
}

void UpdateChecker::finishedSlot(const QString & json)
{
    if(json.isEmpty())
    {
        SimpleErrorBox(mParent, tr("Network Error!"), tr("Failed to check for updates"));
        return;
    }

    QJsonParseError error;
    auto releases = QJsonDocument::fromJson(json.toUtf8(), &error).array();
    if(error.error != QJsonParseError::NoError || releases.isEmpty())
    {
        SimpleErrorBox(mParent, tr("Error!"), tr("File on server could not be parsed..."));
        return;
    }

    QString markdown;
    QString label;
    auto buildDate = GetCompileDate();
    for(int i = 0; i < releases.size(); i++)
    {
        QJsonObject release = releases[i].toObject();
        auto publishedAt = release.value("published_at").toString();
        auto publishedDate = QDateTime::fromString(publishedAt, Qt::ISODate).date();
        auto tagName = release.value("tag_name").toString();

        if(i == 0)
        {
            if(publishedDate <= buildDate)
            {
                QString info;
                if(publishedDate < buildDate)
                {
                    info = QString(tr("You have a development build (%1) of WinInspect!")).arg(ToDateString(buildDate));
                }
                else
                {
                    info = tr("You have the latest build (%1) of WinInspect!").arg(ToDateString(buildDate));
                }
                GuiAddStatusBarMessage((info + "\n").toUtf8().constData());
                SimpleInfoBox(mParent, tr("Information"), info);
                return;
            }

            QString downloadUrl;
            auto assets = release.value("assets").toArray();
            for(int j = 0; j < assets.size(); j++)
            {
                auto asset = assets[i].toObject();
                downloadUrl = asset.value("browser_download_url").toString();
                break;
            }

            label = tr("<p><b>New version available</b>: <a href=\"%1\">%2</a></p>").arg(downloadUrl, tagName);
            GuiAddLogMessageHtml((label + "\n").toUtf8().constData());
        }

        // Do not show release notes older than the current build
        if(publishedDate <= buildDate)
            break;

        auto body = release.value("body").toString();
        if(!body.startsWith("#"))
        {
            markdown += QString("# %1\n").arg(tagName);
        }

        markdown += body;
        markdown += QString("\n\n<sub>%1</sub>").arg(publishedAt);
        markdown += "\n\n";
    }

    mReleaseNotes->move(mParent->frameGeometry().center() - mReleaseNotes->rect().center());
    mReleaseNotes->setMarkdown(markdown, QString());
    mReleaseNotes->setLabel(label);
    mReleaseNotes->exec();
}
