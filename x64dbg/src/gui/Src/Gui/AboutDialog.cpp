#include "AboutDialog.h"
#include "UpdateChecker.h"
#include "ui_AboutDialog.h"
#include <StringUtil.h>
#include <QDesktopServices>
#include <QUrl>
#include "WebLinks.h"

AboutDialog::AboutDialog(UpdateChecker* updateChecker, QWidget* parent) :
    mUpdateChecker(updateChecker),
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    //set window flags
    setModal(true);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint | Qt::MSWindowsFixedSizeDialogHint);

    ui->lblVersion->setText(ToDateString(GetCompileDate()) + ", " __TIME__);
    ui->lblQrImage->installEventFilter(this);
    ui->lblWebsite->setText(QString("<a href=\"%1\">%1</a>").arg(WebLinks::website()));
    ui->lblDonation->setText(QString("Please consider donating using the Bitcoin address on the right or by going to <a href=\"%1\">%1</a>.").arg(WebLinks::donate()));
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

bool AboutDialog::eventFilter(QObject* obj, QEvent* event)
{
    if(obj == ui->lblQrImage && event->type() == QEvent::MouseButtonPress)
        QDesktopServices::openUrl(QUrl("https://blockchain.info/address/1GuXgtCrLk4aYgivAT7xAi8zVHWk5CkEoY"));
    return false;
}

void AboutDialog::on_btnCheckUpdates_clicked()
{
    mUpdateChecker->checkForUpdates();
}
