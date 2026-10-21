import json

import httpx
import pytest

from secure_firewall_assistant.fmc import FMC
from secure_firewall_assistant.security import Redactor, SecretStore
from secure_firewall_assistant.service import Assistant
from secure_firewall_assistant.state import Device, State


class MemoryBackend:
    """Synthetic fixture, never a production credential backend."""

    def __init__(self):
        self.values = {}

    def get_password(self, service, reference):
        return self.values.get((service, reference))

    def set_password(self, service, reference, value):
        self.values[service, reference] = value


class Lab:
    def __init__(self):
        self.calls = []
        self.objects = {}
        self.pending = [{"entityUUID": "net-1", "entityName": "branch", "action": "ADD"}]
        self.override = None
        self.token_count = 0

    def handle(self, request):
        self.calls.append(request)
        path = request.url.path
        if path.endswith("generatetoken") or path.endswith("refreshtoken"):
            self.token_count += 1
            return httpx.Response(204, headers={
                "X-auth-access-token": f"SYNTHETIC-ACCESS-{self.token_count}",
                "X-auth-refresh-token": f"SYNTHETIC-REFRESH-{self.token_count}",
                "DOMAINS": json.dumps([{"name": "Global", "uuid": "domain-1"}])})
        if self.override:
            response = self.override(request)
            if response is not None:
                return response
        if path.endswith("serverversion"):
            return httpx.Response(200, json={"items": [{"serverVersion": "10.5.0.0 (build fixture)"}]})
        if path.endswith("deployabledevices"):
            return httpx.Response(200, json={"items": [{"id": "ftd-1", "name": "lab-ftd-1", "version": "12345",
                                                        "canBeDeployed": True, "isDeploying": False,
                                                        "trafficInterruption": "NO"}]})
        if path.endswith("pendingchanges"):
            return httpx.Response(200, json={"items": self.pending})
        if path.endswith("deploymentrequests"):
            return httpx.Response(202, json={"metadata": {"task": {"id": "task-1"}}, "type": "DeploymentRequest"})
        if path.endswith("object/networks"):
            if request.method == "POST":
                data = json.loads(request.content)
                if isinstance(data, list):
                    items = []
                    for i, value in enumerate(data):
                        record = {**value, "id": f"net-{i+1}"}
                        self.objects[record["id"]] = record
                        items.append(record)
                    return httpx.Response(201, json={"items": items})
                self.objects["net-1"] = {**data, "id": "net-1"}
                return httpx.Response(201, json=self.objects["net-1"])
            return httpx.Response(200, json={"items": list(self.objects.values())})
        if "/object/networks/" in path:
            identifier = path.split("/")[-1]
            if identifier not in self.objects:
                return httpx.Response(404, json={"error": {"messages": [{"description": "Resource absent"}]}})
            if request.method == "PUT":
                self.objects[identifier] = json.loads(request.content)
            elif request.method == "DELETE":
                del self.objects[identifier]
                return httpx.Response(200, json={"id": identifier})
            return httpx.Response(200, json=self.objects[identifier])
        return httpx.Response(404, json={"error": {"messages": [{"description": "Not implemented in fixture"}]}})


@pytest.fixture
def state(tmp_path):
    value = State(tmp_path / "private-config", tmp_path / "private-data", tmp_path / "devices.yaml")
    value.save_device(Device("lab-fmc-1", "fmc", "https://fmc.example.invalid", "fixture-user", "lab-fmc-1-auth", domain="Global"))
    return value


@pytest.fixture
def lab():
    return Lab()


@pytest.fixture
def assistant(state, lab):
    store = SecretStore(Redactor(), state.device_file)
    store.set("lab-fmc-1-auth", "SYNTHETIC-LOGIN-SENTINEL")

    def factory(device, secrets, redactor):
        secrets.redactor = redactor
        return FMC(device, secrets, redactor, transport=httpx.MockTransport(lab.handle))

    value = Assistant(state=state, secrets=store, client_factory=factory)
    yield value
    value.close()
