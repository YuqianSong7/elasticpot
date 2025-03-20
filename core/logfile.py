
from sys import stdout
from datetime import datetime
import json
import clickhouse_connect
from twisted.python import log, util
from twisted.python.logfile import DailyLogFile

# ClickHouse Config
CLICKHOUSE_URL = "http://your-clickhouse-server:8123"
CLICKHOUSE_USER = "your_user"
CLICKHOUSE_PASSWORD = "your_password"
CLICKHOUSE_TABLE = "elasticLogs"

# Table schema
TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS honeypot_logs (
    timestamp DateTime,
    event_id String,
    message String,
    url String,
    source_ip String,
    src_port String,
    dst_port String,
    sensor String,
    request String,
    user_agent String,
    content_type String,
    dst_ip String,
    payload String
) ENGINE = MergeTree()
ORDER BY timestamp;
"""


class HoneypotDailyLogFile(DailyLogFile):
    """
    Overload original Twisted with improved date formatting
    """

    def suffix(self, tupledate):
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        """
        try:
            return "{:02d}-{:02d}-{:02d}".format(tupledate[0], tupledate[1], tupledate[2])
        except Exception:
            # try taking a float unixtime
            return '_'.join(map(str, self.toDate(tupledate)))

    def rotate(self):
        """
        Rotate the log file and upload the previous day's log to ClickHouse
        """
        old_log_path = self.path + "-" + self.suffix(self.toDate())  # Get previous day's filename
        super().rotate()  # Perform Twisted's normal log rotation
        self.upload_to_clickhouse(old_log_path)  # Upload after rotation

    def upload_to_clickhouse(self, file_path):
        """Read JSON logs from file and upload them to ClickHouse."""
        try:
            # Ensure table exists
            self.ensure_table_exists()

            with open(file_path, "r") as f:
                logs = [json.loads(line.strip()) for line in f if line.strip()]  # Parse JSON logs

            if not logs:
                log.msg(f"No data to upload from {file_path}")
                return

            # Ensure all logs have required fields
            formatted_logs = [self.format_log(log) for log in logs]

            # Convert logs into ClickHouse INSERT format
            data = "\n".join(json.dumps(log) for log in formatted_logs)

            # Send data to ClickHouse
            response = requests.post(
                f"{CLICKHOUSE_URL}/?query=INSERT INTO {CLICKHOUSE_TABLE} FORMAT JSONEachRow",
                data=data,
                auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD),
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                log.msg(f"Successfully uploaded {len(logs)} logs from {file_path} to ClickHouse")
            else:
                log.msg(f"Failed to upload logs to ClickHouse: {response.text}")

        except Exception as e:
            log.msg(f"Error uploading logs to ClickHouse: {str(e)}")

    def ensure_table_exists(self):
        """Ensure the ClickHouse table exists before inserting data."""
        try:
            response = requests.post(
                f"{CLICKHOUSE_URL}/?query={TABLE_SCHEMA}",
                auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD),
            )
            if response.status_code != 200:
                log.msg(f"Error creating table: {response.text}")
        except Exception as e:
            log.msg(f"Error ensuring table exists: {str(e)}")

    def format_log(self, log_entry):
        """Ensure all fields exist in the log entry, filling in missing fields with defaults."""
        default_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": "",
            "message": "",
            "url": "",
            "source_ip": "",
            "src_port": "",
            "dst_port": "",
            "sensor": "",
            "request": "",
            "user_agent": "",
            "content_type": "",
            "dst_ip": "",
            "payload": ""
        }
        return {key: log_entry.get(key, default_log[key]) for key in default_log}


def myFLOemit(self, eventDict):
    """
    Format the given log event as text and write it to the output file.

    @param eventDict: a log event
    @type eventDict: L{dict} mapping L{str} (native string) to L{object}
    """

    # Custom emit for FileLogObserver
    text = log.textFromEventDict(eventDict)
    if text is None:
        return
    timeStr = self.formatTime(eventDict['time'])
    fmtDict = {
        'text': text.replace('\n', '\n\t')
    }
    msgStr = log._safeFormat('%(text)s\n', fmtDict)
    util.untilConcludes(self.write, timeStr + ' ' + msgStr)
    util.untilConcludes(self.flush)


def myFLOformatTime(self, when):
    """
    Log time in UTC

    By default it's formatted as an ISO8601-like string (ISO8601 date and
    ISO8601 time separated by a space). It can be customized using the
    C{timeFormat} attribute, which will be used as input for the underlying
    L{datetime.datetime.strftime} call.

    @type when: C{int}
    @param when: POSIX (ie, UTC) timestamp.

    @rtype: C{str}
    """
    timeFormatString = self.timeFormat
    if timeFormatString is None:
        timeFormatString = '[%Y-%m-%d %H:%M:%S.%fZ]'
    return datetime.utcfromtimestamp(when).strftime(timeFormatString)


def set_logger(cfg_options):
    log.FileLogObserver.emit = myFLOemit
    log.FileLogObserver.formatTime = myFLOformatTime
    if cfg_options['logfile'] is None:
        log.startLogging(stdout)
    else:
        log.startLogging(HoneypotDailyLogFile.fromFullPath(cfg_options['logfile']), setStdout=False)
