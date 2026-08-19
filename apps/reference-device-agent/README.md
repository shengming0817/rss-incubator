# Reference Device Agent

This directory reserves the narrow reference device agent identity for Azure PBI #2122. That PBI
will own authenticated MQTT transport, persistent local generation/fence/credential revision, and
the distinction between broker acknowledgement, device ACK, reported state, and application receipt.

This skeleton contains no executable, transport client, credential material, simulator, fleet or
inventory behavior, enrollment, remote control, or CA operation. The future reference agent is not a
production MDM agent.
