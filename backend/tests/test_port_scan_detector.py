from app.services.port_scan_detector import PortScanDetector


def test_port_scan_requires_twenty_unique_tcp_syn_ports_and_triggers_once():
    detector = PortScanDetector()
    base = {
        "source_ip": "192.168.161.129",
        "destination_ip": "192.168.161.128",
        "protocol": "TCP",
        "features": {"SYN Flag Count": 1},
    }

    for port in range(1, 20):
        assert not detector.observe(destination_port=port, **base)

    # Repeated probes of one port must not inflate the unique-port count.
    assert not detector.observe(destination_port=19, **base)
    assert detector.observe(destination_port=20, **base)
    assert not detector.observe(destination_port=21, **base)


def test_port_scan_ignores_non_syn_and_non_tcp_flows():
    detector = PortScanDetector()
    base = {
        "source_ip": "192.168.161.129",
        "destination_ip": "192.168.161.128",
        "features": {"SYN Flag Count": 0},
    }

    for port in range(1, 25):
        assert not detector.observe(protocol="TCP", destination_port=port, **base)
    assert not detector.observe(protocol="UDP", destination_port=25,
                               features={"SYN Flag Count": 1},
                               source_ip=base["source_ip"],
                               destination_ip=base["destination_ip"])
