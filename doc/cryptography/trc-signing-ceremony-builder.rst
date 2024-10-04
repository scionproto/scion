.. _trc-signing-ceremony-builder:

.. raw:: html

    <script src="https://cdn.tailwindcss.com"></script>
    <div class="hidden">

*************************************
TRC Signing Ceremony - Script Builder
*************************************

.. raw:: html

    </div>


.. raw:: html

    <script>

        function formatDateForOpenSSL(date) {
            try {
                return (new Date(date)).toISOString().replace(/[-:.TZ]/g, '').slice(0, 14) + 'Z';
            } catch {
                return '$DATE';
            }
        }
    </script>

    <div x-data="{
        ceremonyType: $persist('base'),
        tool: $persist('scion-pki'),
        actions: $persist([]),
        trc: {
            isd: $persist(1),
            base: $persist(1),
            serial: $persist(1),
        },
        shortId: $persist('shortname'),
        skipPreparation: $persist(false),
        skipPhase1: $persist(false),
        showExpectedOutput: $persist(false),

        form: {
            paths: {
                workingDir: $persist('$WORKDIR'),
            },

            exchange: {
                type: $persist('shared-drive'),
                sharedDrive: $persist('$SHARED_DRIVE'),
            },

            certs: {
                subject: {
                    country: $persist(''),
                    state: $persist(''),
                    locality: $persist(''),
                    organization: $persist(''),
                    organizational_unit: $persist(''),
                    isd_as: $persist(''),
                },
                sensitiveVoting: {
                    key: $persist('$KEYDIR/sensitive-voting.key'),
                    cert: $persist('$PUBDIR/sensitive-voting.crt'),
                    commonName: $persist(''),
                    notBefore: $persist(''),
                    notAfter: $persist(''),
                    defaultSuffix: ' High Security Voting Certificate',
                    kms: $persist('file'),
                    keyLabel: $persist(''),
                },
                regularVoting: {
                    key: $persist('$KEYDIR/regular-voting.key'),
                    cert: $persist('$PUBDIR/regular-voting.crt'),
                    commonName: $persist(''),
                    notBefore: $persist(''),
                    notAfter: $persist(''),
                    defaultSuffix: ' Regular Voting Certificate',
                    kms: $persist('file'),
                    keyLabel: $persist(''),
                },
                root: {
                    key: $persist('$KEYDIR/cp-root.key'),
                    cert: $persist('$PUBDIR/cp-root.crt'),
                    commonName: $persist(''),
                    notBefore: $persist(''),
                    notAfter: $persist(''),
                    defaultSuffix: ' High Security Root Certificate',
                    kms: $persist('file'),
                    keyLabel: $persist(''),
                },
            },
            signatures: {
                sensitiveVote: {
                    key: $persist('$PREV_KEYDIR/sensitive-voting.key'),
                    cert: $persist('$PREV_PUBDIR/sensitive-voting.crt'),
                    kms: $persist('file'),
                },
                regularVote: {
                    key: $persist('$PREV_KEYDIR/regular-voting.key'),
                    cert: $persist('$PREV_PUBDIR/regular-voting.crt'),
                    kms: $persist('file'),
                },
                rootApproval: {
                    key: $persist('$PREV_KEYDIR/cp-root.key'),
                    cert: $persist('$PREV_PUBDIR/cp-root.crt'),
                    kms: $persist('file'),
                },
            },

        },

        now: $persist(''),
        get in5years() {
            let newDate = new Date(Date.parse(this.now));
            newDate.setDate(newDate.getDate() + (365 * 5));
            return newDate;
        },

        get requiredMissing() {
            return this.trc.isd === '' || this.shortId === '' || (this.form.certs.subject.isd_as === '' && this.createAny) ;
        },

        get askForSubject() {
            return this.createAny;
        },

        get createSensitive() {
            return this.actions.includes('replace-sensitive-voting') && this.ceremonyType !== 'regular';
        },

        get createRegular() {
            return this.actions.includes('replace-regular-voting');
        },

        get createRoot() {
            return this.actions.includes('replace-root');
        },

        get createAny() {
            return this.createSensitive || this.createRegular || this.createRoot;
        },

        get castVote() {
            return this.actions.includes('cast-vote');
        },

        get castSensitiveVote() {
            return this.castVote && this.ceremonyType === 'sensitive';
        },

        get castRegularVote() {
            return this.castVote && this.ceremonyType === 'regular';
        },

        get castRootApproval() {
            return this.createRoot && this.ceremonyType === 'regular';
        },

        get newCertsForm() {
            let forms = []
            if (this.createSensitive) {
                forms.push({
                    title: 'New Sensitive Voting Certificate',
                    form: this.form.certs.sensitiveVoting,
                })
            }
            if (this.createRegular) {
                forms.push({
                    title: 'New Regular Voting Certificate',
                    form: this.form.certs.regularVoting,
                })
            }
            if (this.createRoot) {
                forms.push({
                    title: 'New Root Certificate',
                    form: this.form.certs.root,
                })
            }
            return forms
        },

        get newCerts() {
            let certs = []
            if (this.createSensitive) {
                certs.push({
                    title: 'Create Sensitive Voting Certificate',
                    profile: 'sensitive-voting',
                    extKeyUsage: '1.3.6.1.4.1.55324.1.3.1',
                    ...this.form.certs.sensitiveVoting,
                })
            }
            if (this.createRegular) {
                certs.push({
                    title: 'Create Regular Voting Certificate',
                    profile: 'regular-voting',
                    extKeyUsage: '1.3.6.1.4.1.55324.1.3.2',
                    ...this.form.certs.regularVoting,
                })
            }
            if (this.createRoot) {
                certs.push({
                    title: 'Create Root Certificate',
                    profile: 'cp-root',
                    extKeyUsage: '1.3.6.1.4.1.55324.1.3.3',
                    ...this.form.certs.root,
                })
            }
            return certs
        },

        get signaturesForm() {
            let forms = []
            if (this.castSensitiveVote) {
                forms.push({
                    title: 'Cast Sensitive Vote',
                    description: 'The vote is cast by signing the TRC with the private key for which a sensitive voting certificate was included in the predecessor TRC.',
                    form: this.form.signatures.sensitiveVote,
                })
            }
            if (this.castRegularVote) {
                forms.push({
                    title: 'Cast Regular Vote',
                    description: 'The vote is cast by signing the TRC with the private key for which a regular voting certificate was included in the predecessor TRC.',
                    form: this.form.signatures.regularVote,
                })
            }
            if (this.castRootApproval) {
                forms.push({
                    title: 'Show Root Approval',
                    description: 'The root approval is shown by signing the TRC with the private key for which a CPPKI root certificate was included in the predecessor TRC. This is only required if the root certificate is modifed. Note that the subject of the root certificate must be the same as the predecessor.',
                    form: this.form.signatures.rootApproval,
                })
            }
            return forms
        },

        get signatures() {
            let signatures = []
            if (this.createSensitive) {
                const form = this.form.certs.sensitiveVoting;
                signatures.push({
                    title: 'Show Proof-of-Possession for the Sensitive Voting Key',
                    verifyTitle: 'Verify Proof-of-Possession for the Sensitive Voting Key',
                    crt: form.cert,
                    key: form.kms === 'file' ? form.key : form.keyLabel,
                    signed: this.trcPrefix+'.sensitive.pop.trc',
                    kms: form.kms,
                })
            }
            if (this.createRegular) {
                const form = this.form.certs.regularVoting;
                signatures.push({
                    title: 'Show Proof-of-Possession for the Regular Voting Key',
                    verifyTitle: 'Verify Proof-of-Possession for the Regular Voting Key',
                    crt: form.cert,
                    key: form.kms === 'file' ? form.key : form.keyLabel,
                    signed: this.trcPrefix+'.regular.pop.trc',
                    kms: form.kms,
                })
            }
            if (this.castRootApproval) {
                form = this.form.signatures.rootApproval;
                signatures.push({
                    title: 'Show approval for the Root Certificate Change',
                    verifyTitle: 'Verify approval for the Root Certificate Change',
                    crt: form.cert,
                    key: form.key,
                    signed: this.trcPrefix+'.root.approval.trc',
                    kms: form.kms,
                })
            }
            if (this.castSensitiveVote) {
                form = this.form.signatures.sensitiveVote;
                signatures.push({
                    title: 'Cast Vote with Sensitive Voting Certificate',
                    verifyTitle: 'Verify Vote with Sensitive Voting Certificate',
                    crt: form.cert,
                    key: form.key,
                    signed: this.trcPrefix+'.sensitive.vote.trc',
                    kms: form.kms,
                })
            }
            if (this.castRegularVote) {
                form = this.form.signatures.regularVote;
                signatures.push({
                    title: 'Cast Vote with Regular Voting Certificate',
                    verifyTitle: 'Verify Vote with Regular Voting Certificate',
                    crt: form.cert,
                    key: form.key,
                    signed: this.trcPrefix+'.regular.vote.trc',
                    kms: form.kms,
                })
            }
            return signatures
        },

        get subjectTemplate() {
            return JSON.stringify(
                Object.fromEntries(Object.entries(this.form.certs.subject).filter(([key, value]) => value !== '')),
                null,
                2,
            )
        },

        get opensslBasicCnfDN() {
            return Object.entries({
                'C     ': this.form.certs.subject.country,
                'ST    ': this.form.certs.subject.state,
                'L     ': this.form.certs.subject.location,
                'O     ': this.form.certs.subject.organization,
                'OU    ': this.form.certs.subject.organizational_unit,
                'ISD-AS': this.form.certs.subject.isd_as
            })
                .filter(([key, value]) => value !== '')
                .map(([key, value]) => `${key} = ${value}`)
                .join('\n')
        },

        get trcId() {
            return `ISD${this.trc.isd}-B${this.trc.base}-S${this.trc.serial}`;
        },

        get predTrcId() {
            return `ISD${this.trc.isd}-B${this.trc.base}-S${this.trc.serial - 1}`;
        },

        get trcPayload() {
            return `${this.trcPrefix}.pld.der`;
        },

        get trcSigned() {
            return `${this.trcPrefix}.trc`;
        },

        get trcPrefix() {
            return `${this.form.paths.workingDir}/${this.trcId}`;
        },

        get predTrc() {
            return `${this.form.paths.workingDir}/${this.predTrcId}.trc`;
        },

        get phase3offset() {
            if (this.tool === 'scion-pki') {
                return this.signatures.length + 1;
            }
            return (2 * this.signatures.length) + 1;

        },
     }"
     >


    <div class="max-w-xl mx-auto bg-white shadow-lg rounded-lg p-8 my-8">
        <h1 class="text-2xl font-bold mb-6 text-center print:hidden">TRC Ceremony Builder</h1>

        <div class="mb-6">
            <h3 class="text-lg font-semibold mb-4">TRC</h3>
            <table class="min-w-full bg-white border border-gray-300">
                <tbody>
                    <tr>
                        <td class="px-4 py-2 border-b">Ceremony Type</td>
                        <td class="px-4 py-2 border-b">
                            <select id="ceremonyType" x-model="ceremonyType" class="block w-full border rounded-lg px-4 py-2">
                                <option value="sensitive">Sensitive</option>
                                <option value="regular">Regular</option>
                                <option value="base">Base</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">ISD</td>
                        <td class="px-4 py-2 border-b">
                            <input required type="number" x-model="trc.isd" class="block w-full border rounded-lg px-4 py-2">
                            <div x-show="trc.isd === ''" class="text-red-600">ISD required</div>
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Base Number</td>
                        <td class="px-4 py-2 border-b">
                            <input type="number" x-model="trc.base" disabled class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Serial Number</td>
                        <td class="px-4 py-2 border-b">
                            <input type="number" x-model="trc.serial" x-effect="trc.serial = ceremonyType === 'base' ? 1 : (trc.serial === 1 ? 2 : trc.serial)" :disabled="ceremonyType === 'base'" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Actions Table -->
        <div class="mb-6">
            <h3 class="text-lg font-semibold mb-4">Actions</h3>
            <table class="min-w-full bg-white border border-gray-300">
                <thead>
                    <tr>
                        <th class="px-4 py-2 border-b">Select</th>
                        <th class="px-4 py-2 border-b">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr x-show="ceremonyType !== 'regular'">
                        <td class="px-4 py-2 border-b text-center">
                            <input type="checkbox" x-model="actions" value="replace-sensitive-voting" class="form-checkbox h-5 w-5">
                        </td>
                        <td class="px-4 py-2 border-b">New sensitive voting certificate</td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b text-center">
                            <input type="checkbox" x-model="actions" value="replace-regular-voting" class="form-checkbox h-5 w-5">
                        </td>
                        <td class="px-4 py-2 border-b">New regular voting certificate</td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b text-center">
                            <input type="checkbox" x-model="actions" value="replace-root" class="form-checkbox h-5 w-5">
                        </td>
                        <td class="px-4 py-2 border-b">New root certificate</td>
                    </tr>
                    <tr x-show="ceremonyType !== 'base'">
                        <td class="px-4 py-2 border-b text-center">
                            <input type="checkbox" x-model="actions" value="cast-vote" class="form-checkbox h-5 w-5">
                        </td>
                        <td class="px-4 py-2 border-b">Cast a vote</td>
                    </tr>
                </tbody>
            </table>
        </div>

         <!-- Inputs Table -->
         <div class="mb-6">
            <h3 class="text-lg font-semibold mb-4">General Settings</h3>
            <table class="min-w-full bg-white border border-gray-300">
                <tbody>
                    <tr>
                        <td class="px-4 py-2 border-b">Working Directory</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="form.paths.workingDir" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Signing Tool</td>
                        <td class="px-4 py-2 border-b">
                            <select id="tool" x-model="tool" class="block w-full border rounded-lg px-4 py-2">
                                <option value="scion-pki">scion-pki</option>
                                <option value="openssl">openssl</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Short ID</td>
                        <td class="px-4 py-2 border-b">
                            <input required type="text" x-model="shortId" class="block w-full border rounded-lg px-4 py-2" placeholder="used to organize artifacts">
                               <div x-show="shortId === ''" class="text-red-600">Short Identifier required</div>
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Exchange Mechanism</td>
                        <td class="px-4 py-2 border-b">
                            <select x-model="form.exchange.type" class="block w-full border rounded-lg px-4 py-2">
                                <option value="shared-drive">Shared Drive</option>
                                <option value="tar">Tar (manual)</option>
                            </select>
                        </td>
                    </tr>
                    <tr x-show="form.exchange.type === 'shared-drive'">
                        <td class="px-4 py-2 border-b">Shared Drive</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="form.exchange.sharedDrive" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr x-show="createAny">
                        <td class="px-4 py-2 border-b">Skip Preparation</td>
                        <td class="px-4 py-2 border-b text-left">
                            <input type="checkbox" x-model="skipPreparation" class="form-checkbox h-5 w-5">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Skip Certificate Exchange</td>
                        <td class="px-4 py-2 border-b text-left">
                            <input type="checkbox" x-model="skipPhase1" class="form-checkbox h-5 w-5">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Show Expected Output Hints</td>
                        <td class="px-4 py-2 border-b text-left">
                            <input type="checkbox" x-model="showExpectedOutput" class="form-checkbox h-5 w-5">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

         <!-- Inputs Table -->
         <div x-show="askForSubject" class="mb-6">
            <h3 class="text-lg font-semibold mb-4">Certificate Subject</h3>
            <table class="min-w-full bg-white border border-gray-300">
                <tbody>
                    <tr>
                        <td class="px-4 py-2 border-b">ISD-AS</td>
                        <td class="px-4 py-2 border-b">
                            <input required type="text" x-model="form.certs.subject.isd_as" class="block w-full border rounded-lg px-4 py-2">
                            <div x-show="form.certs.subject.isd_as === ''" class="text-red-600">ISD-AS required</div>
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Country</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="form.certs.subject.country" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">State</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="form.certs.subject.state" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Locality</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="form.certs.subject.locality" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Organization</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="form.certs.subject.organization" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Organizational Unit</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="form.certs.subject.organizational_unit" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>


        <!-- Create Sensitive-->
        <template x-for="v in newCertsForm"><div class="mb-6">
            <h3 class="text-lg font-semibold mb-4" x-text="v.title"></h3>
            <table class="min-w-full bg-white border border-gray-300">
                <tbody>
                    <tr>
                        <td class="px-4 py-2 border-b">Common Name</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.commonName" x-effect="v.form.commonName = form.certs.subject.organization+v.form.defaultSuffix" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr x-show="tool === 'openssl'">
                        <td class="px-4 py-2 border-b">Key Management System</td>
                        <td class="px-4 py-2 border-b">
                            <select id="openssl-kms" x-model="v.form.kms" class="block w-full border rounded-lg px-4 py-2">
                                <option value="file">file</option>
                                <option value="pkcs11">pkcs11</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Private Key <span x-show="tool === 'openssl' && v.form.kms !== 'file'"> (URI)</span></td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.key" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr x-show="tool === 'openssl' && v.form.kms !== 'file'">
                        <td class="px-4 py-2 border-b">Private Key (Label for CMS)</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.keyLabel" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Certificate Path</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.cert" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Not Before</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.notBefore" x-effect="v.form.notBefore = now" class="block w-full border rounded-lg px-4 py-2" >
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Not After</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.notAfter" x-effect="v.form.notAfter = in5years.toISOString()" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div></template>



        <!-- Cast Vote-->
        <template x-for="v in signaturesForm" ><div class="mb-6">
            <h3 class="text-lg font-semibold" x-text="v.title"></h3>
            <div class="mb-4 -mt-4 text-slate-500 text-sm" x-text="v.description"></div>
            <table class="min-w-full bg-white border border-gray-300">
                <tbody>
                     <tr x-show="tool === 'openssl'">
                        <td class="px-4 py-2 border-b">Key Management System</td>
                        <td class="px-4 py-2 border-b">
                            <select id="openssl-kms" x-model="v.form.kms" class="block w-full border rounded-lg px-4 py-2">
                                <option value="file">file</option>
                                <option value="pkcs11">pkcs11</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Private Key <span x-show="tool === 'openssl' && v.form.kms !== 'file'"> (Label for CMS)</span></td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.key" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                    <tr>
                        <td class="px-4 py-2 border-b">Certificate</td>
                        <td class="px-4 py-2 border-b">
                            <input type="text" x-model="v.form.cert" class="block w-full border rounded-lg px-4 py-2">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div></template>

        <div class="flex flex-row justify-end gap-x-4 print:hidden">
            <button onclick="window.print()" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Print this page</button>
            <button x-show="createAny" @click="now = (new Date()).toISOString()" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Current Time</button>
        </div>
    </div>

    <template x-if="requiredMissing">
    <div class="bg-red-100 mx-auto border border-red-300 shadow-md rounded-lg p-8 mb-8">
    Some required fields are missing. Please fill out the form completely.
    </div>
    </template>

    <div class="bg-blue-100 mx-auto border border-blue-300 shadow-md rounded-lg p-4 mb-4">
        Check that you are in the correct working directory, if you are using
        relative paths, or environment variables containing relative paths.
        We recommend using absolute paths where possible.
    </div>


    <!-- Preparation Phase -->
    <template x-if="createAny && !skipPreparation"><div class="bg-white mx-auto border border-gray-300 shadow-md rounded-lg p-8 mb-8 print:p-0 print:border-0 print:shadow-none print:pt-8 print:break-before-page">
        <div class="mb-4">
            <h2 id="preparation" class="text-2xl !mb-2">Preparation</h2>
            <div class="text-slate-500 text-sm">
                Execute the following steps to prepare for the TRC ceremony.
                Make sure that you have access to all the required keys and
                certificates during the ceremony. To learn more about the
                process, refer to the <a class="text-blue-600 underline"
                href="./trc-signing-ceremony-preparations.html">preparation
                steps</a>.
            </div>
        </div>


        <template x-if="tool === 'scion-pki'"><div>
            <!-- Configuration Files -->
            <div>
                <h3>1. Create Subject Template<h3>
                <div class="highlight"><pre><div>cat << EOF > <span x-text="form.paths.workingDir"></span>/subject.tmpl
    <span x-text="subjectTemplate"></span>
    EOF</div></pre></div>
            </div>

            <template x-for="(cert, index) in newCerts"><div>
                <h3 x-text="(index+2) + '. ' +cert.title"><h3>
                <div class="highlight"><pre><div>scion-pki certificate create \
        --profile <span x-text="cert.profile"></span> \
        --not-before <span x-text="cert.notBefore"></span> \
        --not-after <span x-text="cert.notAfter"></span> \
        --common-name "<span x-text="cert.commonName"></span>" \
        <span x-text="form.paths.workingDir"></span>/subject.tmpl \
        <span x-text="cert.key"></span> \
        <span x-text="cert.cert"></span></div></pre></div>
            </div></template>
        </div></template>

        <template x-if="tool === 'openssl'"><div>
            <div>
                <h3>1. Create Basic Openssl Configuration<h3>
                <div class="highlight"><pre><div>cat << EOF > <span x-text="form.paths.workingDir"></span>/basic.cnf
    [openssl_init]
    oid_section = oids

    [req]
    distinguished_name = req_distinguished_name
    prompt             = no

    [oids]
    ISD-AS        = SCION ISD-AS number, 1.3.6.1.4.1.55324.1.2.1
    sensitive-key = SCION sensitive voting key, 1.3.6.1.4.1.55324.1.3.1
    regular-key   = SCION regular voting key, 1.3.6.1.4.1.55324.1.3.2
    root-key      = SCION CP root key, 1.3.6.1.4.1.55324.1.3.3

    [req_distinguished_name]
    <span x-text="opensslBasicCnfDN">  </span>
    CN     = \${common_name::name}

    [ca]
    default_ca = basic_ca

    [basic_ca]
    default_days   = \${ca_defaults::default_days}
    default_md     = sha256
    database       = database/index.txt
    new_certs_dir  = certificates
    unique_subject = no
    rand_serial    = yes
    policy         = policy_any

    [policy_any]
    countryName            = supplied
    stateOrProvinceName    = optional
    organizationName       = optional
    organizationalUnitName = optional
    commonName             = supplied
    emailAddress           = optional

    EOF</div></pre></div>

            <div>
                <h3>2. Create x509 Database<h3>
                <div class="highlight"><pre><div>mkdir -p <span x-text="form.paths.workingDir"></span>/database
    touch <span x-text="form.paths.workingDir"></span>/database/index.txt
    mkdir -p <span x-text="form.paths.workingDir"></span>/certificates</div></pre></div>



            <template x-for="(cert, index) in newCerts"><div>
                <h3 x-text="(index+3) + '. ' + cert.title"><h3>
                <div class="highlight"><pre><div>cat << EOF > <span x-text="form.paths.workingDir"></span>/<span x-text="cert.profile"></span>.cnf
    openssl_conf    = openssl_init
    x509_extensions = x509_ext

    [common_name]
    name = <span x-text="cert.commonName"></span>

    [x509_ext]
    subjectKeyIdentifier = hash
    extendedKeyUsage     = <span x-text="cert.extKeyUsage"></span>, 1.3.6.1.5.5.7.3.8

    [ca_defaults]
    default_days = 1825

    .include basic.cnf
    EOF</div></pre></div>

                <div x-show="cert.kms === 'pkcs11'" class="mb-4 text-slate-500">
                    The private key is proviced via PKCS#11. The following
                    command requires that the key has already been created.
                    Follow the documentation of your KMS to create the key.
                </div>

                <div class="highlight"><pre><div><template x-if="cert.kms === 'file'"><span>openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve \
        -out <span x-text="cert.key"></span>

    </span></template>openssl req -new -utf8 \
        -config <span x-text="form.paths.workingDir"></span>/<span x-text="cert.profile"></span>.cnf \
        -key <span x-text="cert.key"></span> \<template x-if="cert.kms === 'pkcs11'"><span>
        -keyform engine \
        -engine pkcs11 \</span></template>
        -out <span x-text="form.paths.workingDir"></span>/<span x-text="cert.profile"></span>.csr

    openssl ca -selfsign -preserveDN -notext -batch -utf8 \
        -in <span x-text="form.paths.workingDir"></span>/<span x-text="cert.profile"></span>.csr \
        -config <span x-text="form.paths.workingDir"></span>/<span x-text="cert.profile"></span>.cnf \
        -keyfile <span x-text="cert.key"></span> \<template x-if="cert.kms === 'pkcs11'"><span>
        -keyform engine \
        -engine pkcs11 \</span></template>
        -startdate <span x-text="formatDateForOpenSSL(cert.notBefore)"></span> \
        -enddate <span x-text="formatDateForOpenSSL(cert.notAfter)"></span> \
        -out <span x-text="cert.cert"></span></div></pre></div>
            </div></template>

        </div></template>

    </div></template>

    <!-- Phase 1 -->
    <template x-if="!skipPhase1"><div class="bg-white mx-auto border border-gray-300 shadow-md rounded-lg p-8 mb-8 print:p-0 print:border-0 print:shadow-none print:pt-8 print:break-before-page">
        <div class="mb-4">
            <h2 id="phase-1" class="text-2xl !mb-2">Phase 1: Exchange of Certificates</h2>
            <div class="text-slate-500 text-sm">
                Follow the instructions of the TRC ceremony adminstrator to
                exchange all of the required certificates.
            </div>
        </div>

        <template x-if="createAny && form.exchange.type === 'shared-drive'"><div>
            <h3>1. Copy own certificates to drive</h3>
            <div class="highlight"><pre><div>mkdir -p <span x-text="form.exchange.sharedDrive"></span>/<span x-text="shortId"></span>
    cp <template x-if="createSensitive"><span><span x-text="form.certs.sensitiveVoting.cert"></span> \
       </span></template><template x-if="createRegular"><span><span x-text="form.certs.regularVoting.cert"></span> \
       </span></template><template x-if="createRoot"><span><span x-text="form.certs.root.cert"></span> \
       </span></template><span x-text="form.exchange.sharedDrive"></span>/<span x-text="shortId"></span></div></pre></div>
        </div></template>

        <template x-if="createAny && form.exchange.type === 'tar'"><div>
            <h3 class="!mb-0">1. Share certificate bundle</h3>
            <div class="text-slate-500 text-sm mb-2">
                Share the tar file with the TRC ceremony administrator using the agreed upon
                manual channel.
            </div>
            <div class="highlight"><pre><div>tar --transform 's|.*/|<span x-text="shortId"></span>/|' \
       <template x-if="createSensitive"><span><span x-text="form.certs.sensitiveVoting.cert"></span> \
       </span></template><template x-if="createRegular"><span><span x-text="form.certs.regularVoting.cert"></span> \
       </span></template><template x-if="createRoot"><span><span x-text="form.certs.root.cert"></span> \
       </span></template>-cvf <span x-text="trcId"></span>.<span x-text="shortId"></span>.certs.tar</div></pre></div>
        </div></template>


        <template x-if="form.exchange.type === 'shared-drive'"><div>
            <h3 x-text="(createAny ? 2 : 1 ) + '. Copy all certificates from drive'"></h3>
            <div class="highlight"><pre><div>cp -r <span x-text="form.exchange.sharedDrive"></span>/*/ <span x-text="form.paths.workingDir"></span>/</div></pre></div>
        </div></template>

        <template x-if="form.exchange.type === 'tar'"><div>
            <h3 x-text="(createAny ? 2 : 1 ) + '. Unpack certificate bundle'"></h3>
            <div class="highlight"><pre><div>tar -xf <span x-text="trcId"></span>.certs.tar -C <span x-text="form.paths.workingDir"></span></div></pre></div>
        </div></template>

        <div>
            <h3 x-text="(createAny ? 3 : 2 ) + '. Check exchanged certificates'"></h3>
            <div class="highlight"><pre><div>for cert in <span x-text="form.paths.workingDir"></span>/*/*.crt; do
        sha256sum $cert
    done</div></pre></div>

            <template x-if="showExpectedOutput"><div>
                <div class="text-slate-500 text-sm">Expected Output:</div>
                <div class="highlight"><pre><div>521908d5ebefddd536a... FILE_NAME</div></pre></div>
            </div></template>
        </div>
    </div></template>

    <!-- Phase 2 -->
    <div class="bg-white mx-auto border border-gray-300 shadow-md rounded-lg p-8 mb-8 print:break-before-page print:p-0 print:border-0 print:shadow-none print:pt-8">
        <div class="mb-4">
            <h2 id="phase-2" class="text-2xl !mb-2">Phase 2: Creation of Payload</h2>
            <div class="text-slate-500 text-sm">
                Follow the instructions of the TRC ceremony adminstrator to
                receive the TRC payload.
            </div>
        </div>

        <template x-if="form.exchange.type === 'shared-drive'"><div>
            <h3>1. Copy TRC Payload</h3>
            <div class="highlight"><pre><div>cp <span x-text="form.exchange.sharedDrive"></span>/<span x-text=trcId></span>.pld.der <span x-text="trcPayload"></span></div></pre></div>
        </div></template>

        <template x-if="form.exchange.type === 'tar'"><div>
            <h3>1. Unpack TRC Payload</h3>
            <div class="highlight"><pre><div>tar -xf <span x-text=trcId></span>.pld.tar -C <span x-text="form.paths.workingDir"></span></div></pre></div>
        </div></template>

        <div>
            <h3>2. Check TRC Payload</h3>
            <div class="highlight"><pre><div>sha256sum <span x-text="trcPayload"></span></div></pre></div>

            <template x-if="showExpectedOutput"><div>
                <div class="text-slate-500 text-sm">Expected Output:</div>
                <div class="highlight"><pre><div>fe37bb0d2462f3ffe86... <span x-text="trcPayload"></span></div></pre></div>
            </div></template>
        </div>

        <div>
            <h3>3. Inspect TRC Payload</h3>
            <div class="highlight"><pre><div>scion-pki trc inspect <span x-text="trcPayload"></span></div></pre></div>

            <template x-if="showExpectedOutput"><div>
                <div class="text-slate-500 text-sm">Expected Output:</div>
                <div class="highlight"><pre><div>version: 1
    id:
      isd: <span x-text="trc.isd"></span>
      base_number: <span x-text="trc.base"></span>
      serial_number: <span x-text="trc.serial"></span>
    ...</div></pre></div>
            </div></template>
        </div>
    </div>

    <!-- Phase 3 -->
    <div class="bg-white mx-auto border border-gray-300 shadow-md rounded-lg p-8 mb-8 print:break-before-page print:p-0 print:border-0 print:shadow-none print:pt-8">
        <div class="mb-4">
            <h2 id="phase-3" class="text-2xl !mb-2">Phase 3: Signing of the TRC Payload</h2>
            <div class="text-slate-500 text-sm">
                Follow the instructions of the TRC ceremony adminstrator and
                create the required signatures.
            </div>
        </div>

        <template x-for="(v, index) in signatures">
            <div>
                <h3 x-text="(index + 1) + '. ' + v.title"></h3>
                <template x-if="tool === 'scion-pki'">
                    <div class="highlight"><pre><div>scion-pki trc sign <span x-text="trcPayload"></span> \
        <span x-text="v.crt"></span> \
        <span x-text="v.key"></span> \
        -o <span x-text="v.signed"></span></div></pre></div>
                </template>
                <template x-if="tool === 'openssl'"><div>
                    <div class="highlight"><pre><div>openssl cms -sign -in <span x-text="trcPayload"></span> -inform der \
        -signer <span x-text="v.crt"></span> \
        -inkey <span x-text="v.key"></span> \<template x-if="v.kms === 'pkcs11'"><span>
        -keyform engine \
        -engine pkcs11 \</span></template>
        -nodetach -nocerts -nosmimecap -binary -outform der \
        > <span x-text="v.signed"></span></div></pre></div>

                    <template x-if="showExpectedOutput"><div>
                        <div class="text-slate-500 text-sm">Expected Output:</div>
                        <div x-show="v.kms === 'pkcs11'" class="highlight"><pre><div>engine "pkcs11" set.</div></pre></div>
                        <div x-show="v.kms !== 'pkcs11'" class="highlight"><pre><div><i>silent</i></div></pre></div>
                    </div></template>
                </div></template>
            </div>
        </template>

        <template x-for="(v, index) in (tool === 'openssl' ? signatures : [])">
            <div>
                <h3 x-text="(index + 1 + signatures.length) + '. ' + v.verifyTitle"></h3>
                    <div class="highlight"><pre><div>openssl cms -verify -in <span x-text="v.signed"></span> -inform der \
        -certfile <span x-text="v.crt"></span> \
        -CAfile <span x-text="v.crt"></span> \
        -purpose any -no_check_time \
        > /dev/null</div></pre></div>

                <template x-if="showExpectedOutput"><div>
                    <div class="text-slate-500 text-sm">Expected Output:</div>
                    <div class="highlight"><pre><div>Verification successful</div></pre></div>
                </div></template>
            </div>
        </template>

        <template x-if="signatures && signatures.length !== 0 && form.exchange.type === 'shared-drive'"><div>
            <h3 x-text="phase3offset + '. Copy own signatures to drive'"></h3>
            <div class="highlight"><pre><div>cp <template x-for="s in signatures"><span><span x-text="s.signed"></span> \
       </span></template><span x-text="form.exchange.sharedDrive"></span>/<span x-text="shortId"></span></div></pre></div>
        </div></template>

        <template x-if="signatures && signatures.length !== 0 && form.exchange.type === 'tar'"><div>
            <h3 x-text="phase3offset + '. Bundle own signatures'"></h3>
            <div class="highlight"><pre><div>tar --transform 's|.*/|<span x-text="shortId"></span>/|' \
       <template x-for="s in signatures"><span><span x-text="s.signed"></span> \
       </span></template>-cvf <span x-text="trcId"></span>.<span x-text="shortId"></span>.signatures.tar</div></pre></div>
        </div></template>
    </div>

    <!-- Phase 4 -->
    <div class="bg-white mx-auto border border-gray-300 shadow-md rounded-lg p-8 mb-8 print:break-before-page print:p-0 print:border-0 print:shadow-none print:pt-8">
        <div class="mb-4">
            <h2 id="phase-4" class="text-2xl !mb-2">Phase 4: Assembly of the TRC</h2>
            <div class="text-slate-500 text-sm">
                Follow the instructions of the TRC ceremony adminstrator to
                recieve the signed TRC. This step concludes the ceremony.
            </div>
        </div>

        <template x-if="form.exchange.type === 'shared-drive'"><div>
            <h3>1. Copy TRC from drive</h3>
            <div class="highlight"><pre><div>cp <span x-text="form.exchange.sharedDrive"></span>/<span x-text=trcId></span>.trc <span x-text="trcSigned"></span></div></pre></div>
        </div></template>

        <template x-if="form.exchange.type === 'tar'"><div>
            <h3>1. Unpack TRC</h3>
            <div class="highlight"><pre><div>tar -xf <span x-text=trcId></span>.trc.tar -C <span x-text="form.paths.workingDir"></span></div></pre></div>
        </div></template>

        <div>
            <h3>2. Check TRC</h3>
            <div class="highlight"><pre><div>sha256sum <span x-text="trcSigned">.trc</span></div></pre></div>

            <template x-if="showExpectedOutput"><div>
                <div class="text-slate-500 text-sm">Expected Output:</div>
                <div class="highlight"><pre><div>b43cd88fddf9032f7b2... <span x-text="trcSigned">.trc</div></pre></div>
            </div></template>
        </div>

        <div>
            <h3>3. Inspect TRC</h3>
            <div class="highlight"><pre><div>scion-pki trc inspect <span x-text="trcSigned"></span> --predecessor <span x-text="predTrc"></span></div></pre></div>

            <template x-if="showExpectedOutput"><div>
                <div class="text-slate-500 text-sm">Expected Output:</div>
                <div class="highlight"><pre><div>version: 1
    id:
      isd: <span x-text="trc.isd"></span>
      base_number: <span x-text="trc.base"></span>
      serial_number: <span x-text="trc.serial"></span>
    ...</div></pre></div>
            </div></template>
        </div>

        <div>
            <h3 class="!mb-0">4. Format TRC</h3>
            <div class="text-slate-500 text-sm mb-2">
                The output of the TRC ceremony is a DER encoded TRC. To convert
                it to a more ergonomic PEM format, use the following command.
            </div>
            <div class="highlight"><pre><div>scion-pki trc format <span x-text="trcSigned"></span> --format pem</div></pre></div>

            <template x-if="showExpectedOutput"><div>
                <div class="text-slate-500 text-sm">Expected Output:</div>
                <div class="highlight"><pre><div>-----BEGIN TRC-----
    MIIRpQYJKoZIhvcNAQcCoIIRljCCEZICAQExDTALBglghkgBZQMEAgEwggx0Bgkq
    hkiG9w0BBwGgggxlBIIMYTCCDF0CAQAwCQIBAQIBAQIBATAiGA8yMDI0MDgyNjE1
    MTUxNFoYDzIwMjUxMTE5MTUxNTE0WgIBAAEBADAAAgECMBgTCmZmMDA6MDoxMjAT
    ...</div></pre></div>
            </div></template>
        </div>
    </div>

    </div>

