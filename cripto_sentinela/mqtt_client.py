import paho.mqtt.client as mqtt
import json

class MQTTClient:
    def __init__(self, config, on_msg_callback):
        self.config = config
        self.client = mqtt.Client()
        self.client.on_connect = self._on_connect
        self.client.on_message = on_msg_callback
        self.client.connect(config["mqtt_broker"], config["mqtt_port"], keepalive=60)
        self.subs = []

    def _on_connect(self, client, userdata, flags, rc):
        for topic in self.subs:
            self.client.subscribe(topic)

    def subscribe(self, topic):
        self.subs.append(topic)
        self.client.subscribe(topic)

    def publish(self, topic, payload, retain=False):
        self.client.publish(topic, payload, retain=retain)

    def start(self):
        self.client.loop_start()

    def stop(self):
        self.client.loop_stop()
