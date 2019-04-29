/**
 *
 * Copyright 2014-2019 Florian Schmaus
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smack.tcp;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.Writer;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.tcp.XMPPTCPConnection.PacketWriter;

import org.junit.Test;
import org.jxmpp.stringprep.XmppStringprepException;

public class PacketWriterTest {
    private volatile boolean shutdown;
    private volatile boolean prematureUnblocked;

    /**
     * Make sure that stanza writer does block once the queue reaches
     * {@link PacketWriter#QUEUE_SIZE} and that
     * {@link PacketWriter#sendStanza(org.jivesoftware.smack.tcp.packet.Packet)} does unblock after the
     * interrupt.
     *
     * @throws InterruptedException
     * @throws BrokenBarrierException
     * @throws NotConnectedException
     * @throws XmppStringprepException
     */
    @Test
    public void shouldBlockAndUnblockTest() throws InterruptedException, BrokenBarrierException, NotConnectedException, XmppStringprepException {
        XMPPTCPConnection connection = new XMPPTCPConnection("user", "pass", "example.org");
        final PacketWriter pw = connection.packetWriter;
        BlockingStringWriter blockingStringWriter = new BlockingStringWriter();
        connection.setWriter(blockingStringWriter);
        connection.packetWriter.init();

        // Now insert QUEUE_SIZE + 1 stanzas into the outgoing queue to make sure that the queue is filled until its
        // full capacity. The +1 is because the writer thread will dequeue one stanza and try to write it into the
        // blocking writer.
        for (int i = 0; i < XMPPTCPConnection.PacketWriter.QUEUE_SIZE + 1; i++) {
            pw.sendStreamElement(new Message());
        }

        final CyclicBarrier barrier = new CyclicBarrier(2);
        final AtomicReference<Exception> unexpectedThreadExceptionReference = new AtomicReference<>();
        final AtomicReference<Exception> expectedThreadExceptionReference = new AtomicReference<>();
        shutdown = false;
        prematureUnblocked = false;
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    barrier.await();
                    pw.sendStreamElement(new Message());
                    // should only return after the pw was interrupted
                    if (!shutdown) {
                        prematureUnblocked = true;
                    }
                }
                catch (SmackException.NotConnectedException e) {
                    // This is the exception we expect.
                    expectedThreadExceptionReference.set(e);
                }
                catch (BrokenBarrierException | InterruptedException e) {
                    unexpectedThreadExceptionReference.set(e);
                }

                try {
                    barrier.await();
                }
                catch (InterruptedException | BrokenBarrierException e) {
                    unexpectedThreadExceptionReference.set(e);
                }
            }
        });
        t.start();
        // This barrier is not strictly necessary, but may increases the chances that the threat
        // will block before we call shutdown. Otherwise we may get false positives (which is still
        // better then false negatives).
        barrier.await();
        // Not really cool, but may increases the chances for 't' to block in sendStanza.
        Thread.sleep(250);

        // Set to true for testing purposes, so that shutdown() won't wait packet writer
        pw.shutdownDone.reportSuccess();
        // Shutdown the packetwriter, this will also interrupt the writer thread, which is what we hope to happen in the
        // thread created above.
        pw.shutdown(false);
        shutdown = true;
        barrier.await();

        t.join(60000);

        Exception unexpectedThreadException = unexpectedThreadExceptionReference.get();
        try {
            if (prematureUnblocked) {
                String failureMessage = "Should not unblock before the thread got shutdown.";
                if (unexpectedThreadException != null) {
                    failureMessage += " Unexpected thread exception thrown: " + unexpectedThreadException;
                }
                fail(failureMessage);
            }
            else if (unexpectedThreadException != null) {
                fail("Unexpected thread exception: " + unexpectedThreadException);
            }

            assertNotNull("Did not encounter expected exception on sendStreamElement()", expectedThreadExceptionReference.get());
        }
        finally {
            blockingStringWriter.unblock();
        }
    }

    public static class BlockingStringWriter extends Writer {
        private boolean blocked = true;

        @Override
        public void write(char[] cbuf, int off, int len) throws IOException {
            synchronized (this) {
                while (blocked) {
                    try {
                        wait();
                    }
                    catch (InterruptedException e) {
                        throw new AssertionError(e);
                    }
                }
            }
        }

        public synchronized void unblock() {
            blocked = false;
            notify();
        }

        @Override
        public void flush() throws IOException {
        }

        @Override
        public void close() throws IOException {
        }
    }
}
