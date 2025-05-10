/*
 *  Copyright (C) 2025 KeePassXC Team <team@keepassxc.org>
 *  Copyright (C) 2014 Kyle Manna <kyle@kylemanna.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "YubiKey.h"
#include "YubiKeyInterfacePCSC.h"
#include "YubiKeyInterfaceUSB.h"

#include <QMutexLocker>
#include <QSet>
#include <QtConcurrent>

YubiKey::YubiKey()
{
    int num_interfaces = 0;

    if (YubiKeyInterfaceUSB::instance()->isInitialized()) {
        ++num_interfaces;
        connect(YubiKeyInterfaceUSB::instance(), SIGNAL(challengeStarted()), this, SIGNAL(challengeStarted()));
        connect(YubiKeyInterfaceUSB::instance(), SIGNAL(challengeCompleted()), this, SIGNAL(challengeCompleted()));
    } else {
        qDebug("YubiKey: USB interface is not initialized.");
    }

    if (YubiKeyInterfacePCSC::instance()->isInitialized()) {
        ++num_interfaces;
        connect(YubiKeyInterfacePCSC::instance(), SIGNAL(challengeStarted()), this, SIGNAL(challengeStarted()));
        connect(YubiKeyInterfacePCSC::instance(), SIGNAL(challengeCompleted()), this, SIGNAL(challengeCompleted()));
    } else {
        qDebug("YubiKey: PC/SC interface is disabled or not initialized.");
    }

    m_initialized = num_interfaces > 0;

    m_interactionTimer.setSingleShot(true);
    m_interactionTimer.setInterval(200);
    connect(&m_interactionTimer, SIGNAL(timeout()), this, SIGNAL(userInteractionRequest()));
    connect(this, &YubiKey::challengeStarted, this, [this] { m_interactionTimer.start(); });
    connect(this, &YubiKey::challengeCompleted, this, [this] { m_interactionTimer.stop(); });
}

YubiKey* YubiKey::m_instance(nullptr);

YubiKey* YubiKey::instance()
{
    if (!m_instance) {
        m_instance = new YubiKey();
    }

    return m_instance;
}

bool YubiKey::isInitialized()
{
    return m_initialized;
}

// Conflict 1 Resolution: Keep both findValidKeys overloads.
bool YubiKey::findValidKeys()
{
    // RESOLVED: Adopted m_interfaces_detect_mutex from 'main' (771ea431) for detection.
    QMutexLocker lock(&m_interfaces_detect_mutex);

    m_connectedKeys = 0;
    m_findingKeys = true;
    m_usbKeys = YubiKeyInterfaceUSB::instance()->findValidKeys(m_connectedKeys);
    m_pcscKeys = YubiKeyInterfacePCSC::instance()->findValidKeys(m_connectedKeys);
    m_findingKeys = false;

    return !m_usbKeys.isEmpty() || !m_pcscKeys.isEmpty();
}

void YubiKey::findValidKeys(const QMutexLocker<QRecursiveMutex>& locker)
{
    // Check QMutexLocker since version 6.4
    Q_UNUSED(locker);

    m_connectedKeys = 0;
    m_usbKeys = YubiKeyInterfaceUSB::instance()->findValidKeys(m_connectedKeys);
    m_pcscKeys = YubiKeyInterfacePCSC::instance()->findValidKeys(m_connectedKeys);
}
// End Conflict 1 Resolution

void YubiKey::findValidKeysAsync()
{
    // RESOLVED: Kept the HEAD logic to prevent re-entrant scan using m_findingKeys.
    // Don't start another scan if we are already doing one
    if (!m_findingKeys) {
        m_findingKeys = true;
        QtConcurrent::run([this] { emit detectComplete(findValidKeys()); });
    }
}

YubiKey::KeyMap YubiKey::foundKeys()
{
    // RESOLVED: Adopted QMutexLocker from 'main' (771ea431) for thread-safe map access.
    QMutexLocker lock(&m_interfaces_detect_mutex);
    KeyMap foundKeys = m_usbKeys;
    foundKeys.unite(m_pcscKeys);

    return foundKeys;
}

// Conflict 2 Resolution: Adopt the QMutexLocker from main (f87883a2).
int YubiKey::connectedKeys()
{
    QMutexLocker lock(&m_interfaces_detect_mutex);
    return m_connectedKeys;
}
// End Conflict 2 Resolution

QString YubiKey::errorMessage()
{
    // RESOLVED: Adopted the comprehensive error reporting from 'main' (771ea431).
    QMutexLocker lock(&m_interfaces_detect_mutex);

    QString error;
    error.clear();
    if (!m_error.isNull()) {
        error += tr("General: ") + m_error;
    }

    QString usb_error = YubiKeyInterfaceUSB::instance()->errorMessage();
    if (!usb_error.isNull()) {
        if (!error.isNull()) {
            error += " | ";
        }
        error += "USB: " + usb_error;
    }

    QString pcsc_error = YubiKeyInterfacePCSC::instance()->errorMessage();
    if (!pcsc_error.isNull()) {
        if (!error.isNull()) {
            error += " | ";
        }
        error += "PCSC: " + pcsc_error;
    }

    return error;
}

/**
 * Issue a test challenge to the specified slot to determine if challenge
 * response is properly configured.
 *
 * @param slot YubiKey configuration slot
 * @param wouldBlock return if the operation requires user input
 * @return whether the challenge succeeded
 */
bool YubiKey::testChallenge(YubiKeySlot slot, bool* wouldBlock)
{
    QMutexLocker lock(&m_interfaces_detect_mutex);

    if (m_usbKeys.contains(slot)) {
        return YubiKeyInterfaceUSB::instance()->testChallenge(slot, wouldBlock);
    }

    if (m_pcscKeys.contains(slot)) {
        return YubiKeyInterfacePCSC::instance()->testChallenge(slot, wouldBlock);
    }

    return false;
}

/**
 * Issue a challenge to the specified slot
 * This operation could block if the YubiKey requires a touch to trigger.
 *
 * @param slot YubiKey configuration slot
 * @param challenge challenge input to YubiKey
 * @param response response output from YubiKey
 * @return challenge result
 */
YubiKey::ChallengeResult
YubiKey::challenge(YubiKeySlot slot, const QByteArray& challenge, Botan::secure_vector<char>& response)
{
    // RESOLVED: Adopted QMutexLocker from 'main' (771ea431) to prevent challenges during detection.
    // NOTE: The next line was a redefinition of 'lock' that causes a compile error, renamed to 'detect_lock'
    QMutexLocker detect_lock(&m_interfaces_detect_mutex);

    m_error.clear();

    // Prevent re-entrant access to hardware keys
    // NOTE: The next line was a redefinition of 'lock', renamed to 'interface_lock'
    QMutexLocker interface_lock(&s_interfaceMutex);

    // Try finding key on the USB interface first
    auto ret = YubiKeyInterfaceUSB::instance()->challenge(slot, challenge, response);
    if (ret == ChallengeResult::YCR_ERROR) {
        m_error = YubiKeyInterfaceUSB::instance()->errorMessage();
        return ret;
    }

    // If a USB key was not found, try PC/SC interface
    if (ret == ChallengeResult::YCR_KEYNOTFOUND) {
        ret = YubiKeyInterfacePCSC::instance()->challenge(slot, challenge, response);
        if (ret == ChallengeResult::YCR_ERROR) {
            m_error = YubiKeyInterfacePCSC::instance()->errorMessage();
            return ret;
        }
    }

    if (ret == ChallengeResult::YCR_KEYNOTFOUND) {
        m_error =
            tr("Could not find hardware key with serial number %1. Please connect it to continue.").arg(slot.first);
    }

    return ret;
}