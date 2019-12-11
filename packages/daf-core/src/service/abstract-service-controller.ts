import { EventEmitter } from 'events'
import { Issuer } from '../identity/identity-manager'
import { Resolver } from '../core'
import { Message } from '../message/message'

export enum ServiceEventTypes {
  NewMessages = 'NewMessages',
}

export abstract class AbstractServiceController extends EventEmitter {
  constructor(readonly issuer: Issuer, readonly didResolver: Resolver) {
    super()
  }
  abstract instanceId(): { did: string; type: string; id: string }
  abstract getMessagesSince(timestamp: number): Promise<Message[]>
  abstract listen(): void
}

type AbstractServiceControllerClass = typeof AbstractServiceController
export interface ServiceControllerDerived extends AbstractServiceControllerClass {}
