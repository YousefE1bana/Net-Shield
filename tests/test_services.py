from netshield.services import ssh_outcome


def test_only_trusted_sshd_failed_password_outcomes_are_accepted():
    record = {
        "_COMM": "sshd",
        "_UID": "0",
        "_SYSTEMD_UNIT": "ssh.service",
        "__REALTIME_TIMESTAMP": "1700000000000000",
        "MESSAGE": "Failed password for invalid user private_name from 10.77.0.2 port 40001 ssh2",
    }
    result = ssh_outcome(record, "10.77.0.10")
    assert result["outcome"] == "failure" and result["source_ip"] == "10.77.0.2"
    assert "private_name" not in str(result)
    assert ssh_outcome({**record, "_COMM": "logger"}, "10.77.0.10") is None
    assert ssh_outcome({**record, "_UID": "1000"}, "10.77.0.10") is None
    assert (
        ssh_outcome({**record, "MESSAGE": "Connection closed by 10.77.0.2 port 40001"}, "10.77.0.10") is None
    )
